// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import (
	"net"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/bond"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

const vlanLinkType = "vlan"

// desiredInput is everything one pass computes its allow-list from.
type desiredInput struct {
	routes       []netlink.Route
	links        []netlink.Link
	slots        map[uint32]uint8
	ownLocator   netip.Prefix
	domain       []netip.Prefix
	minPrefixLen int
	binding      Binding
	extra        []netip.Prefix
	// nextHops, when non-empty, are the only gateways a hop may use.
	nextHops []netip.Prefix
	// uplinks is the set of uplink ifindexes. A hop checked against nextHops
	// must also leave through one of them.
	uplinks map[int]bool
}

// desiredOutput is a pass's allow-list plus what it was built from.
type desiredOutput struct {
	entries []Entry
	// fromRoutes counts entries derived from at least one route.
	fromRoutes int
	// unbound counts route entries with a hop whose link is unknown, which
	// are accepted on any interface rather than bound to none.
	unbound int
	// foreignNextHop counts routes dropped because no hop's gateway is a
	// fabric next hop.
	foreignNextHop int
}

// computeDesired returns the allow-list for in, sorted by prefix, with
// duplicate prefixes merged.
//
// A route yields an entry when it is an IPv6 main-table route that forwards,
// was installed by the fabric's routing (BGP or galactic-router), its
// destination lies inside a domain prefix, is at least minPrefixLen long, and
// does not lie inside this node's own locator. When nextHops is set, only hops
// whose gateway lies inside it and that leave through an uplink count, and a
// route with no such hop yields nothing.
//
// Its interface mask is the union of every counted hop's link slots, a bond
// master or a VLAN on a bond counting as its slaves. Loose binding, or a hop
// with no usable link, accepts the prefix on any interface. Every extra prefix
// is accepted on any interface.
func computeDesired(in desiredInput) desiredOutput {
	byIndex := make(map[int]netlink.Link, len(in.links))
	for _, l := range in.links {
		byIndex[l.Attrs().Index] = l
	}

	merged := make(map[netip.Prefix]*Entry)
	fromRoute := make(map[netip.Prefix]bool)
	merge := func(e Entry) {
		cur, ok := merged[e.Prefix]
		if !ok {
			merged[e.Prefix] = &e
			return
		}
		cur.IfaceMask |= e.IfaceMask
		cur.AnyIface = cur.AnyIface || e.AnyIface
	}

	var out desiredOutput
	for i := range in.routes {
		r := &in.routes[i]
		p, ok := routePrefix(r)
		if !ok || !in.eligible(p) {
			continue
		}
		mask, bound, ok := in.hopMask(r, byIndex)
		if !ok {
			out.foreignNextHop++
			continue
		}
		e := Entry{Prefix: p, IfaceMask: mask, AnyIface: in.binding == BindingLoose || !bound}
		if !bound {
			out.unbound++
		}
		merge(e)
		fromRoute[p] = true
	}
	for _, p := range in.extra {
		merge(Entry{Prefix: p.Masked(), AnyIface: true})
	}

	out.entries = make([]Entry, 0, len(merged))
	for _, e := range merged {
		out.entries = append(out.entries, *e)
	}
	slices.SortFunc(out.entries, func(a, b Entry) int { return a.Prefix.Compare(b.Prefix) })
	out.fromRoutes = len(fromRoute)
	return out
}

// eligible reports whether p is a fabric peer's prefix: inside a domain
// prefix, at least minPrefixLen long and not inside this node's own locator.
func (in desiredInput) eligible(p netip.Prefix) bool {
	if p.Bits() < in.minPrefixLen {
		return false
	}
	if in.ownLocator.IsValid() && contains(in.ownLocator, p) {
		return false
	}
	for _, d := range in.domain {
		if contains(d, p) {
			return true
		}
	}
	return false
}

// contains reports whether inner lies entirely inside outer.
func contains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// routePrefix returns r's destination when r is an IPv6 main-table route that
// forwards somewhere. A discard or local route, a default route and an IPv4
// route all return false.
func routePrefix(r *netlink.Route) (netip.Prefix, bool) {
	if r.Table != unix.RT_TABLE_MAIN || r.Dst == nil {
		return netip.Prefix{}, false
	}
	if r.Type != unix.RTN_UNICAST && r.Type != unix.RTN_UNSPEC {
		return netip.Prefix{}, false
	}
	if !fabricProtocol(r.Protocol) {
		return netip.Prefix{}, false
	}
	ones, bits := r.Dst.Mask.Size()
	if bits != net.IPv6len*8 || ones == 0 {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok || !addr.Is6() || addr.Is4In6() || addr.IsLinkLocalUnicast() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones).Masked(), true
}

// fabricProtocol reports whether p is a route protocol the fabric's own
// routing installs with: the underlay's BGP, or galactic-router.
func fabricProtocol(p netlink.RouteProtocol) bool {
	return p == unix.RTPROT_BGP || p == srv6.RouteProtocolGalactic
}

// hopMask returns the union of the slots of every counted link r's hops leave
// through, whether every counted hop named a link that could be resolved, and
// whether any hop counted at all. Without nextHops every hop counts.
func (in desiredInput) hopMask(r *netlink.Route, byIndex map[int]netlink.Link) (uint32, bool, bool) {
	type hop struct {
		link int
		gw   net.IP
	}
	hops := make([]hop, 0, 1+len(r.MultiPath))
	if len(r.MultiPath) > 0 {
		for _, nh := range r.MultiPath {
			hops = append(hops, hop{link: nh.LinkIndex, gw: nh.Gw})
		}
	} else {
		hops = append(hops, hop{link: r.LinkIndex, gw: r.Gw})
	}

	var (
		mask    uint32
		bound   = true
		counted bool
	)
	for _, h := range hops {
		if len(in.nextHops) > 0 && !in.fabricNextHop(h.link, h.gw) {
			continue
		}
		counted = true
		link, ok := byIndex[h.link]
		if h.link <= 0 || !ok {
			bound = false
			continue
		}
		for _, idx := range ingressLinks(link, byIndex, in.links) {
			if slot, ok := in.slots[uint32(idx)]; ok && int(slot) < MaxSlots {
				mask |= 1 << slot
			}
		}
	}
	if !bound {
		mask = 0
	}
	return mask, bound, counted
}

// fabricNextHop reports whether a hop through link to gw reaches a fabric BGP
// peer: gw lies inside a nextHops prefix and link is an uplink.
func (in desiredInput) fabricNextHop(link int, gw net.IP) bool {
	if !in.uplinks[link] {
		return false
	}
	addr, ok := netip.AddrFromSlice(gw)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range in.nextHops {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ingressLinks returns the ifindexes a packet routed out of link can arrive
// on: link itself, plus its slaves when link is a bond master, plus the slaves
// of the bond a VLAN link sits on. Receive classification on a bond happens on
// its slaves, so a slave's ifindex is what the datapath sees.
func ingressLinks(link netlink.Link, byIndex map[int]netlink.Link, all []netlink.Link) []int {
	out := []int{link.Attrs().Index}
	master := link
	if !bond.IsMaster(master) {
		if link.Type() != vlanLinkType {
			return out
		}
		parent, ok := byIndex[link.Attrs().ParentIndex]
		if !ok || !bond.IsMaster(parent) {
			return out
		}
		master = parent
		out = append(out, parent.Attrs().Index)
	}
	for _, l := range all {
		if l.Attrs().MasterIndex == master.Attrs().Index {
			out = append(out, l.Attrs().Index)
		}
	}
	return out
}
