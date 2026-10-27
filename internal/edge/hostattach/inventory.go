// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/nldump"
)

const aliasPrefix = "galactic-edge:hostattach:"
const vethType = "veth"

func ownerAlias(id string) string { return aliasPrefix + id }

// LinkID is the ID galactic-edge stamps on an attachment's links: the VPC
// identifier and the EdgeAttachment's UID. The UID makes a recreated
// attachment a different owner; the VPC names the ownership scope a link
// belongs to, and tells maintenance which VPC a link with no attachment left
// still uses.
func LinkID(vpc, uid string) string { return vpc + "." + uid }

// ParseLinkID splits an ID LinkID made. ok is false for any other ID.
func ParseLinkID(id string) (vpc, uid string, ok bool) {
	vpc, uid, ok = strings.Cut(id, ".")
	return vpc, uid, ok && vpc != "" && uid != ""
}

// ObservedAttachment identifies an owned host link, including partial attempts.
// It is observed kernel state, not a substitute for authorized durable intent.
type ObservedAttachment struct {
	ID          string
	HostLink    string
	HostIndex   int
	MasterIndex int
}

// List lists stamped host veths for restart reconciliation, including links
// created before any VRF or route was configured. Callers match IDs to their
// durable inventory before resuming or releasing resources.
func List(host *Namespace) ([]ObservedAttachment, error) {
	if err := host.Verify(); err != nil {
		return nil, err
	}
	h, err := host.netlink()
	if err != nil {
		return nil, err
	}
	defer func() { _ = h.Close() }()
	return listOwned(h)
}

// ListHost is List over the caller's own network namespace. Its netlink
// socket is opened in place rather than by entering a namespace, so it needs
// no CAP_SYS_ADMIN: a process that holds only CAP_NET_ADMIN, such as
// galactic-router, can call it from the host's namespace.
func ListHost() ([]ObservedAttachment, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("hostattach: netlink handle in the current network namespace: %w", err)
	}
	defer func() { _ = h.Close() }()
	return listOwned(h)
}

func listOwned(h *netlink.Handle) ([]ObservedAttachment, error) {
	links, err := nldump.On(h).LinkList()
	if err != nil {
		return nil, fmt.Errorf("hostattach: list owned links: %w", err)
	}
	var result []ObservedAttachment
	for _, l := range links {
		id, owned := strings.CutPrefix(l.Attrs().Alias, aliasPrefix)
		if l.Type() != vethType || !owned || id == "" {
			continue
		}
		result = append(result, ObservedAttachment{ID: id, HostLink: l.Attrs().Name,
			HostIndex: l.Attrs().Index, MasterIndex: l.Attrs().MasterIndex})
	}
	return result, nil
}

// podDefault is the destination of the only route an attachment's pod link
// carries in the pod VRF.
var podDefault = netip.PrefixFrom(netip.IPv6Unspecified(), 0)

// installed is a route the node installs through an attachment's link: its
// destination and, for a route with one, its gateway.
type installed struct {
	dst netip.Prefix
	gw  netip.Addr
}

// hostRoutes are the routes the node installs through the host link: the
// attachment's address, and each prefix via that address.
func hostRoutes(a Attachment) []installed {
	routes := make([]installed, 0, len(a.Prefixes)+1)
	routes = append(routes, installed{dst: netip.PrefixFrom(a.Address, 128)})
	for _, p := range a.Prefixes {
		routes = append(routes, installed{dst: p, gw: a.Address})
	}
	return routes
}

// podRoutes is the route the node installs through the pod link: the pod
// VRF's default, via the host link's link-local address.
var podRoutes = []installed{{dst: podDefault, gw: hostLinkLocal}}

// tunRoutes are the routes the node installs through the packet device: one
// per prefix, without a gateway.
func tunRoutes(a Attachment) []installed {
	routes := make([]installed, 0, len(a.Prefixes))
	for _, p := range a.Prefixes {
		routes = append(routes, installed{dst: p})
	}
	return routes
}

// matches reports whether r is the installed route: the same destination
// and gateway, at the default metric the node's writes leave.
func (want installed) matches(r netlink.Route) bool {
	if !sameDst(r.Dst, want.dst) || (r.Priority != 0 && r.Priority != defaultRouteMetric) {
		return false
	}
	gw, _ := netip.AddrFromSlice(r.Gw)
	return gw.Unmap() == want.gw
}

// defaultRouteMetric is the metric the kernel gives an IPv6 route added
// without one.
const defaultRouteMetric = 1024

// linkLocalPrefix is the kernel's connected route for any link-local
// address, which every link carries.
var linkLocalPrefix = netip.MustParsePrefix("fe80::/64")

// connected lists the kernel's connected routes the node expects through
// one of an attachment's links: the link-local prefix, and the prefixes of
// the addresses the node itself assigns to the link.
func connected(own ...netip.Addr) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(own)+1)
	prefixes = append(prefixes, linkLocalPrefix)
	for _, a := range own {
		prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	return prefixes
}

// extraRoutes lists the unicast routes through a dedicated owned link that
// the node does not install: any destination, gateway or metric other than
// want's. A kernel route counts as the kernel's own only when it is one of
// the connected routes the node expects (see connected), never because the
// link happens to carry an address now, so neither a route written with
// "proto kernel" nor the connected route of an address someone else added
// is exempt. Local and multicast routes, and routes through other links, are
// never candidates.
func extraRoutes(h *netlink.Handle, index int, table uint32, want []installed, kernel []netip.Prefix,
) ([]netlink.Route, error) {
	routes, err := nldump.On(h).RouteListFiltered(unix.AF_INET6, &netlink.Route{Table: int(table), LinkIndex: index},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, fmt.Errorf("hostattach: list attachment routes: %w", err)
	}
	var extras []netlink.Route
	for _, r := range routes {
		if r.Type != unix.RTN_UNICAST {
			continue
		}
		if r.Protocol == unix.RTPROT_KERNEL && slices.ContainsFunc(kernel, func(p netip.Prefix) bool {
			return sameDst(r.Dst, p)
		}) {
			continue
		}
		if !slices.ContainsFunc(want, func(w installed) bool { return w.matches(r) }) {
			extras = append(extras, r)
		}
	}
	return extras, nil
}

// extraAddrs lists the IPv6 addresses on link other than link-local ones and
// own, the addresses the node assigns to it.
func extraAddrs(h *netlink.Handle, link netlink.Link, own []netip.Addr) ([]netlink.Addr, error) {
	addrs, err := nldump.On(h).AddrList(link, unix.AF_INET6)
	if err != nil {
		return nil, fmt.Errorf("hostattach: list addresses on %q: %w", link.Attrs().Name, err)
	}
	var extras []netlink.Addr
	for _, a := range addrs {
		addr, ok := netip.AddrFromSlice(a.IP)
		if !ok || addr.Unmap().IsLinkLocalUnicast() || slices.Contains(own, addr.Unmap()) {
			continue
		}
		extras = append(extras, a)
	}
	return extras, nil
}

// pruneAddrs removes the addresses extraAddrs finds on link.
func pruneAddrs(h *netlink.Handle, link netlink.Link, own []netip.Addr) error {
	extras, err := extraAddrs(h, link, own)
	if err != nil {
		return err
	}
	for _, a := range extras {
		if err := h.AddrDel(link, &a); err != nil {
			return fmt.Errorf("hostattach: remove stray address %s from %q: %w", a.IPNet, link.Attrs().Name, err)
		}
	}
	return nil
}

func pruneRoutes(h *netlink.Handle, index int, table uint32, want []installed, kernel []netip.Prefix) error {
	extras, err := extraRoutes(h, index, table, want, kernel)
	if err != nil {
		return err
	}
	for _, r := range extras {
		if err := h.RouteDel(&r); err != nil {
			return fmt.Errorf("hostattach: remove stale route %s: %w", r.Dst, err)
		}
	}
	return nil
}
