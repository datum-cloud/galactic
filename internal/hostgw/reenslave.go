// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostgw

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/nldump"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// MasterlessResult reports one ReenslaveMasterlessHostLinks pass.
type MasterlessResult struct {
	// Reenslaved is how many masterless host links the pass enslaved back
	// to their VPC's VRF.
	Reenslaved int
	// Masterless is how many host links still have no master after the
	// pass: their VPC's VRF does not exist, or re-enslaving failed.
	Masterless int
}

// vrfLocked runs a function under the node's VRF lock; a variable so tests
// can run without the node-wide lock file.
var vrfLocked = vrf.Locked

// ReenslaveMasterlessHostLinks finds every Galactic host link (a tap or the
// host end of a veth, named for its VPC and attachment) that has no master,
// and enslaves it back to its VPC's VRF when that VRF exists.
//
// A host link loses its master when its VRF is deleted under it. Before
// garbage collection checked for enslaved links, a pass during a VPC's first
// ADDs could delete the VRF, and a later ADD recreated it. The link then
// routes its guest's traffic in the main table, outside the tenant's VRF,
// and only another ADD for the same attachment re-enslaved it, which a
// running VM never triggers.
//
// Enslaving cycles an up link, which drops its IPv6 addresses, the static
// routes through it and its neighbor entries. So the pass records them first
// and restores them after, in the VRF's table, the way tap repair on ADD
// would leave them. An up link stays up, and a down link, such as one
// quarantined for traffic policy, stays down. The kernel refuses a route
// through a down link, so a down link gets its routes when it is brought up.
// A link whose VRF is gone is only counted: creating the VRF is ADD's job.
//
// The pass runs under the VRF lock, so it never sees a link an ADD is in the
// middle of creating and enslaving. Errors are per link and never stop the
// pass; the error joins them.
func ReenslaveMasterlessHostLinks() (MasterlessResult, error) {
	var result MasterlessResult
	err := vrfLocked(func() error {
		links, err := nldump.LinkList()
		if err != nil {
			return fmt.Errorf("list links: %w", err)
		}
		vrfs := make(map[string]*netlink.Vrf)
		for _, l := range links {
			if v, ok := l.(*netlink.Vrf); ok {
				vrfs[v.Name] = v
			}
		}
		var errs []error
		for _, link := range links {
			attrs := link.Attrs()
			vpc, _, ok := intf.ParseInterfaceNameHost(attrs.Name)
			if !ok || attrs.MasterIndex != 0 {
				continue
			}
			vrfLink, ok := vrfs[intf.GenerateInterfaceNameVRF(vpc)]
			if !ok {
				slog.Warn("Host link has no VRF master and its VPC's VRF does not exist; its guest is routed outside the VPC",
					"hostInterface", attrs.Name, "vpc", vpc)
				result.Masterless++
				continue
			}
			if err := reenslave(link, vrfLink); err != nil {
				errs = append(errs, fmt.Errorf("re-enslave %s to %s: %w", attrs.Name, vrfLink.Name, err))
				result.Masterless++
				continue
			}
			slog.Warn("Re-enslaved host link that had lost its VRF master",
				"hostInterface", attrs.Name, "vpc", vpc, "vrf", vrfLink.Name, "table", vrfLink.Table)
			result.Reenslaved++
		}
		return errors.Join(errs...)
	})
	return result, err
}

// linkState is what enslaving a link to a VRF can drop from it.
type linkState struct {
	up     bool
	addrs  []netlink.Addr
	routes []netlink.Route
	neighs []netlink.Neigh
}

// reenslave enslaves link to vrfLink and restores what the move dropped.
func reenslave(link netlink.Link, vrfLink *netlink.Vrf) error {
	before, err := captureLinkState(link, vrfLink.Table)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetMaster(link, vrfLink); err != nil {
		return fmt.Errorf("enslave: %w", err)
	}
	return restoreLinkState(link.Attrs().Index, vrfLink.Table, before)
}

// captureLinkState records link's admin state, its addresses other than
// IPv6 link-local ones, the static unicast routes through it in tableID, and
// its permanent neighbor entries. Routes in any other table, the main table
// included, are left out: nothing Galactic installs puts a host link's route
// there, and moving one into the tenant's table could route the tenant
// somewhere it should not reach.
func captureLinkState(link netlink.Link, tableID uint32) (linkState, error) {
	st := linkState{up: link.Attrs().Flags&net.FlagUp != 0}
	idx := link.Attrs().Index
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		addrs, err := nldump.AddrList(link, family)
		if err != nil {
			return st, fmt.Errorf("list addresses: %w", err)
		}
		for _, a := range addrs {
			if a.IP.IsLinkLocalUnicast() {
				continue
			}
			st.addrs = append(st.addrs, a)
		}
		routes, err := nldump.RouteListFiltered(family,
			&netlink.Route{LinkIndex: idx, Table: unix.RT_TABLE_UNSPEC},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
		if err != nil {
			return st, fmt.Errorf("list routes: %w", err)
		}
		for _, r := range routes {
			if r.Type != unix.RTN_UNICAST || r.Protocol == unix.RTPROT_KERNEL || r.Dst == nil {
				continue
			}
			if r.Table != int(tableID) {
				continue
			}
			st.routes = append(st.routes, r)
		}
		neighs, err := nldump.NeighList(idx, family)
		if err != nil {
			return st, fmt.Errorf("list neighbors: %w", err)
		}
		for _, n := range neighs {
			if n.State&netlink.NUD_PERMANENT != 0 {
				st.neighs = append(st.neighs, n)
			}
		}
	}
	return st, nil
}

// restoreLinkState puts back on the link with index idx what before
// recorded, and brings it back up if it was up. A route is added only where
// none exists, never replacing one. The kernel adds the connected and local
// routes of each restored address to the VRF's table itself. Each step is
// idempotent.
func restoreLinkState(idx int, tableID uint32, before linkState) error {
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return fmt.Errorf("find link after enslaving: %w", err)
	}
	if before.up && link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("bring back up: %w", err)
		}
	}
	var errs []error
	for _, a := range before.addrs {
		addr := netlink.Addr{IPNet: a.IPNet, Flags: a.Flags, Scope: a.Scope, Broadcast: a.Broadcast}
		if err := netlink.AddrAdd(link, &addr); err != nil && !errors.Is(err, unix.EEXIST) {
			errs = append(errs, fmt.Errorf("restore address %s: %w", a.IPNet, err))
		}
	}
	for _, n := range before.neighs {
		neigh := netlink.Neigh{
			LinkIndex: idx, Family: n.Family, State: netlink.NUD_PERMANENT, IP: n.IP, HardwareAddr: n.HardwareAddr,
		}
		if err := netlink.NeighSet(&neigh); err != nil {
			errs = append(errs, fmt.Errorf("restore neighbor %s: %w", n.IP, err))
		}
	}
	if !before.up {
		return errors.Join(errs...)
	}
	for _, r := range before.routes {
		route := netlink.Route{
			// Of the route's flags only onlink is set by a writer; the
			// rest, such as linkdown on a tap without carrier, are the
			// kernel's to report and refused on add.
			Dst: r.Dst, Gw: r.Gw, Flags: r.Flags & int(netlink.FLAG_ONLINK), LinkIndex: idx, Table: int(tableID),
			Scope: r.Scope, Priority: r.Priority, Protocol: r.Protocol, Src: r.Src,
		}
		if err := netlink.RouteAdd(&route); err != nil && !errors.Is(err, unix.EEXIST) {
			errs = append(errs, fmt.Errorf("restore route %s in table %d: %w", r.Dst, tableID, err))
		}
	}
	return errors.Join(errs...)
}
