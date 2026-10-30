// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vrf manages the Linux VRF interfaces that isolate Galactic VPC
// networks. Each VPC gets one VRF with its own routing table ID per node,
// shared by every attachment landing on that VPC on that node rather than one
// per attachment. Requires CAP_NET_ADMIN.
package vrf

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/nldump"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// SidecarTableIDBase splits the routing table ID space between the two
// writers of the shared pinned eBPF maps. The host's VRFs take IDs below it,
// and the ingress sidecar's take IDs above it.
//
// Each network namespace allocates table IDs on its own, but
// egress_route_table is keyed by table ID alone and is shared between the
// host and every sidecar pod on the node. Without disjoint ranges, a sidecar
// VRF and a host tenant VRF both start at table 1 and overwrite each other's
// routes.
const SidecarTableIDBase = uint32(0x10000)

// HostTableIDMin and HostTableIDMax bound the routing table IDs Add allocates.
// HostTableIDMax stops short of SidecarTableIDBase: the host's installer keeps
// its sidecar return-path tables in the host namespace in the IDs between the
// two (internal/installer/sidecarreturn.go).
const (
	HostTableIDMin = uint32(1)
	HostTableIDMax = uint32(0xEFFF)
)

// UnreachableDefaultMetric is the metric of the unreachable default route Add
// installs in every VRF table, for each family. It is the value the kernel's
// own VRF documentation (Documentation/networking/vrf.rst) recommends: high
// enough that any real default route installed in the table, such as the
// ingress sidecar's, always wins over it.
const UnreachableDefaultMetric = 4278198272

// ErrNotFound is wrapped by TableID when no VRF interface for that VPC exists
// in this process's own network namespace.
//
// Callers need that distinguishable from a genuine netlink failure, because
// absent is an ordinary condition for some of them: a process in the host's
// root namespace legitimately cannot see a VRF the ingress sidecar created
// inside a pod's namespace, while a failed link listing is a real problem
// either way.
var ErrNotFound = errors.New("vrf: no VRF interface for this VPC in this network namespace")

// ErrTableOutOfRange is wrapped by AddInRange when this VPC's VRF already exists
// with a table ID outside the caller's range, for instance one created by an
// ingress sidecar version that allocated from the host's range.
var ErrTableOutOfRange = errors.New("vrf: existing VRF's table is outside the caller's range")

// ErrInUse is wrapped by DeleteIfUnused when a link is still enslaved to the VRF.
var ErrInUse = errors.New("vrf: a link is still enslaved to the VRF")

// vrfMu serializes VRF creation and deletion within one process. It does not by
// itself protect two separate CNI invocations racing on the same node, each
// being its own process, so every holder also takes a cross-process lock
// (see Locked).
var vrfMu sync.Mutex

// Add creates the Linux VRF interface for a base62-encoded VPC, with a routing
// table ID in [HostTableIDMin, HostTableIDMax], and applies the required
// sysctls. The ID is the VPC's reserved one when it has a reservation on this
// node, and otherwise the lowest that no VRF and no reservation holds (see
// Reservation).
//
// The VRF is shared by every attachment on this VPC on this node, so concurrent
// calls, from goroutines here or from separate plugin processes attaching
// different pods, are serialized. It is idempotent by name: a VRF that already
// exists, whether created by a sibling attachment or left behind by a failed
// ADD, returns nil.
//
// Every call, including one that finds the VRF already present, ensures the
// table's unreachable defaults (see ensureUnreachableDefaults). A VRF created
// before those existed therefore gains them on its next attachment's ADD,
// with no migration step.
func Add(vpc string) error {
	return AddInRange(vpc, HostTableIDMin, HostTableIDMax)
}

// AddInRange is Add with the routing table ID allocated from [minID, maxID].
// A VRF that already exists under this VPC's name with a table ID outside that
// range is an error: its table may collide with the other writer's, and
// recreating it would strand whatever is already routed through it.
func AddInRange(vpc string, minID, maxID uint32) error {
	return Locked(func() error {
		_, err := addLocked(vpc, minID, maxID)
		return err
	})
}

// EnsureAndEnslave creates or reuses vpc's VRF, as Add does, then calls
// enslave with it while still holding the lock Add and DeleteIfUnused take.
// enslave creates the caller's host link and enslaves it to the VRF.
//
// Holding the lock across both steps means DeleteIfUnused, which deletes a VRF
// only when no link is enslaved to it, never sees the VRF between its creation
// and the caller's enslavement. A VRF error is wrapped as "add VRF"; enslave's
// error is returned unchanged.
func EnsureAndEnslave(vpc string, enslave func(vrfLink *netlink.Vrf) error) error {
	return Locked(func() error {
		vrfLink, err := addLocked(vpc, HostTableIDMin, HostTableIDMax)
		if err != nil {
			return fmt.Errorf("add VRF: %w", err)
		}
		return enslave(vrfLink)
	})
}

// Locked runs fn while holding the in-process and cross-process VRF locks
// that Add, EnsureAndEnslave, Delete and DeleteIfUnused take. A caller that
// decides from what is enslaved to a VRF uses it so that no EnsureAndEnslave
// can change the answer before fn returns. fn must not call another function
// in this package that takes the lock.
func Locked(fn func() error) error {
	vrfMu.Lock()
	defer vrfMu.Unlock()

	lock, err := acquireLock()
	if err != nil {
		return err
	}
	defer func() { _ = lock.close() }()

	return fn()
}

// addLocked is AddInRange's body, run with vrfMu and the cross-process lock
// held. It returns the VRF link.
func addLocked(vpc string, minID, maxID uint32) (*netlink.Vrf, error) {
	name := intf.GenerateInterfaceNameVRF(vpc)

	if link, err := netlink.LinkByName(name); err == nil {
		existing, ok := link.(*netlink.Vrf)
		if !ok {
			return nil, fmt.Errorf("interface %q exists but is a %s, not a VRF", name, link.Type())
		}
		if existing.Table < minID || existing.Table > maxID {
			return nil, fmt.Errorf("VRF %q has table %d, not in [%d,%d]: %w",
				name, existing.Table, minID, maxID, ErrTableOutOfRange)
		}
		// Record the table this VRF holds, so a VRF created before
		// reservations existed keeps its table if it is ever recreated. A
		// failure here does not fail an ADD onto a VRF that works.
		if err := recordExistingTable(name, existing.Table, minID, maxID); err != nil {
			slog.Warn("vrf: could not record existing VRF's table ID reservation",
				"vrf", name, "table", existing.Table, "err", err)
		}
		return existing, ensureUnreachableDefaults(existing.Table)
	}

	vrfID, err := reserveVRFTable(name, minID, maxID)
	if err != nil {
		return nil, err
	}

	if err := FlushTable(vrfID); err != nil {
		return nil, err
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: vrfID,
	}

	if err := netlink.LinkAdd(vrf); err != nil {
		return nil, err
	}

	if err := sysctl.ConfigureInterfaceSysctls(name); err != nil {
		return nil, err
	}

	// Installed before the VRF comes up, so no packet is ever routed in it
	// without the catch-all in place.
	if err := ensureUnreachableDefaults(vrfID); err != nil {
		return nil, err
	}

	if err := netlink.LinkSetUp(vrf); err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	created, ok := link.(*netlink.Vrf)
	if !ok {
		return nil, fmt.Errorf("interface %q exists but is a %s, not a VRF", name, link.Type())
	}
	return created, nil
}

// ensureUnreachableDefaults installs an unreachable default route for IPv4
// and IPv6 in VRF table tableID, at UnreachableDefaultMetric.
//
// Without it, a lookup that misses in the VRF's table does not stop there.
// The l3mdev rule only selects the table, and a miss falls through to the
// rules after it, ending in the main table. A tenant packet the eBPF datapath
// does not claim would then be routed by the host's own routes, out the
// node's default interface with the tenant's source address. The kernel's
// VRF documentation calls for exactly this route to prevent that. A packet
// with no route in its VRF now fails there, and the sender gets an ICMP
// unreachable.
//
// Idempotent: the route is replaced rather than added.
func ensureUnreachableDefaults(tableID uint32) error {
	defaults := []*net.IPNet{
		{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
	for _, dst := range defaults {
		route := &netlink.Route{
			Dst:      dst,
			Table:    int(tableID),
			Type:     unix.RTN_UNREACHABLE,
			Priority: UnreachableDefaultMetric,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("install unreachable default %s in VRF table %d: %w", dst, tableID, err)
		}
	}
	return nil
}

// Delete flushes every route from the VRF's routing table and removes the
// interface for a base62-encoded VPC. Idempotent: an absent interface returns
// nil.
//
// It does not check what is enslaved to the VRF. Its production caller is
// the ingress sidecar, inside its own pod's network namespace, where it owns
// every link in the VRF. Anything deleting a VRF in the host namespace, where
// CNI ADDs enslave links concurrently, uses DeleteIfUnused instead.
func Delete(vpc string) error {
	return DeleteInRange(vpc, HostTableIDMin, HostTableIDMax)
}

// DeleteInRange is Delete for a VRF whose table was allocated from [minID,
// maxID], as AddInRange does. Its table ID reservation in that range is
// released whether or not the VRF still exists: the caller owns every link in
// this namespace's VRF and removes the state keyed by its table itself, so the
// table is released here rather than quarantined for garbage collection, and
// a retry after a failed release still releases it.
func DeleteInRange(vpc string, minID, maxID uint32) error {
	return Locked(func() error {
		name := intf.GenerateInterfaceNameVRF(vpc)

		// Only a VRF known to be gone releases its table: one a failed
		// listing could not see may still route through it.
		vrfID, err := getVRFIDForInterface(name)
		switch {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			return err
		default:
			if err := FlushTable(vrfID); err != nil {
				return err
			}
			link, err := netlink.LinkByName(name)
			var notFound netlink.LinkNotFoundError
			switch {
			case errors.As(err, &notFound):
			case err != nil:
				return err
			default:
				if err := netlink.LinkDel(link); err != nil {
					return err
				}
			}
		}
		return releaseNameLocked(name, minID, maxID)
	})
}

// DeleteIfUnused flushes the routing table of the VRF interface named name
// and removes it, unless a link is still enslaved to it. It decides under the
// same lock EnsureAndEnslave holds, so it never removes a VRF a concurrent
// ADD has created but not yet populated. It takes the interface name rather
// than the VPC so that garbage collection can remove a VRF under a legacy
// name too.
//
// removed is false when the interface is already gone. The error wraps
// ErrInUse when a link is enslaved, and is an error when name is not a VRF.
func DeleteIfUnused(name string) (removed bool, err error) {
	err = Locked(func() error {
		links, err := nldump.LinkList()
		if err != nil {
			return fmt.Errorf("list links: %w", err)
		}
		var vrfLink *netlink.Vrf
		for _, l := range links {
			if l.Attrs().Name != name {
				continue
			}
			v, ok := l.(*netlink.Vrf)
			if !ok {
				return fmt.Errorf("interface %q is a %s, not a VRF", name, l.Type())
			}
			vrfLink = v
			break
		}
		if vrfLink == nil {
			return nil
		}
		if slaves := EnslavedTo(links, vrfLink.Attrs().Index); len(slaves) > 0 {
			return fmt.Errorf("VRF %q holds %d link(s) %v: %w", name, len(slaves), slaves, ErrInUse)
		}
		if err := FlushTable(vrfLink.Table); err != nil {
			return fmt.Errorf("flush routing table %d: %w", vrfLink.Table, err)
		}
		if err := netlink.LinkDel(vrfLink); err != nil {
			return err
		}
		removed = true
		return nil
	})
	return removed, err
}

// EnslavedTo returns the names of the links in links whose master is the
// interface with index masterIndex.
func EnslavedTo(links []netlink.Link, masterIndex int) []string {
	var names []string
	for _, l := range links {
		if l.Attrs().MasterIndex == masterIndex {
			names = append(names, l.Attrs().Name)
		}
	}
	return names
}

// TableID returns the Linux routing table ID for a base62-encoded VPC's VRF.
// The error wraps ErrNotFound when no such interface exists in this process's
// own network namespace, which some callers treat as ordinary rather than a
// failure.
func TableID(vpc string) (uint32, error) {
	return getVRFIDForInterface(intf.GenerateInterfaceNameVRF(vpc))
}

// Exists reports whether a VRF interface for the given VPC exists in the
// kernel.
func Exists(vpc string) error {
	name := intf.GenerateInterfaceNameVRF(vpc)
	if _, err := netlink.LinkByName(name); err != nil {
		return fmt.Errorf("VRF interface %q not found", name)
	}
	return nil
}

// FlushTable removes every IPv4 and IPv6 route from the given routing table.
// Add calls it before creating a VRF on a reused table ID, which happens when a
// previous VRF was removed without going through Delete, and Delete calls it
// before removing the interface, so a stale table is always cleared rather than
// inherited.
//
// Exported so garbage collection's fallback path, which removes a legacy-named
// interface directly rather than through Delete, can flush the table itself and
// get the same guarantee.
func FlushTable(vrfID uint32) error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := nldump.RouteListFiltered(
			family,
			&netlink.Route{Table: int(vrfID)},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return err
		}
		for _, route := range routes {
			if err := netlink.RouteDel(&route); err != nil {
				return err
			}
		}
	}
	return nil
}

// ListVRFLinks returns all VRF interfaces currently present on the host.
//
// The link dump goes through nldump, so link churn from other processes on
// the node retries the dump instead of failing it. TableID, Add and the
// sidecar's startup inventory all list through here.
func ListVRFLinks() ([]*netlink.Vrf, error) {
	links, err := nldump.LinkList()
	if err != nil {
		return nil, err
	}

	vrfLinks := make([]*netlink.Vrf, 0, len(links))
	for _, link := range links {
		if v, ok := link.(*netlink.Vrf); ok {
			vrfLinks = append(vrfLinks, v)
		}
	}
	return vrfLinks, nil
}

func listVRFLinks() ([]*netlink.Vrf, error) {
	return ListVRFLinks()
}

// recordExistingTable records table as the reservation of the existing VRF
// named name, writing the file only when that changes it (see recordTable).
// Called with the lock held.
func recordExistingTable(name string, table, minID, maxID uint32) error {
	res, err := loadReservations()
	if err != nil {
		return err
	}
	res, changed := recordTable(res, name, table, minID, maxID)
	if !changed {
		return nil
	}
	return saveReservations(res)
}

// reserveVRFTable reserves the table ID in [minID, maxID] for a new VRF named
// name, which is name's own earlier reservation when it has one (see
// reserveTable). The reservation is saved before the caller creates the VRF,
// so a VRF never exists without one. Called with the lock held.
func reserveVRFTable(name string, minID, maxID uint32) (uint32, error) {
	vrfs, err := listVRFLinksFn()
	if err != nil {
		return 0, err
	}
	live := make(map[uint32]string, len(vrfs))
	for _, vrf := range vrfs {
		live[vrf.Table] = vrf.Name
	}
	res, err := loadReservations()
	if err != nil {
		return 0, err
	}
	table, res, err := reserveTable(res, live, name, minID, maxID)
	if err != nil {
		return 0, err
	}
	if err := saveReservations(res); err != nil {
		return 0, err
	}
	return table, nil
}

// nextFreeTableID returns the lowest table ID in [minID, maxID] that is
// neither in used nor one of the kernel's reserved tables (253 default, 254
// main, 255 local). A VRF bound to main would route its tenant through the
// host's own table.
func nextFreeTableID(used map[uint32]struct{}, minID, maxID uint32) (uint32, error) {
	for vrfID := uint64(minID); vrfID <= uint64(maxID); vrfID++ {
		id := uint32(vrfID)
		if id == unix.RT_TABLE_DEFAULT || id == unix.RT_TABLE_MAIN || id == unix.RT_TABLE_LOCAL {
			continue
		}
		if _, ok := used[id]; !ok {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no available VRF table id in [%d,%d]", minID, maxID)
}

func getVRFIDForInterface(name string) (uint32, error) {
	vrfs, err := listVRFLinks()
	if err != nil {
		return 0, err
	}

	vrfByName := make(map[string]*netlink.Vrf, len(vrfs))
	for _, vrf := range vrfs {
		vrfByName[vrf.Name] = vrf
	}

	if vrf, ok := vrfByName[name]; ok {
		return vrf.Table, nil
	}
	return 0, fmt.Errorf("could not find VRF ID for interface %s: %w", name, ErrNotFound)
}
