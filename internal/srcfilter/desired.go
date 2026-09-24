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
}

// desiredOutput is a pass's allow-list plus what it was built from.
type desiredOutput struct {
	entries []Entry
	// fromRoutes counts entries derived from at least one route.
	fromRoutes int
	// unbound counts route entries with a hop whose link is unknown, which
	// are accepted on any interface rather than bound to none.
	unbound int
}

// computeDesired returns the allow-list for in, sorted by prefix, with
// duplicate prefixes merged.
//
// A route yields an entry when it is an IPv6 main-table route that forwards,
// its destination lies inside a domain prefix, is at least minPrefixLen long,
// and does not lie inside this node's own locator. Its interface mask is the
// union of every hop's link slots, a bond master or a VLAN on a bond counting
// as its slaves. Loose binding, or a hop with no usable link, accepts the
// prefix on any interface. Every extra prefix is accepted on any interface.
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
		mask, bound := hopMask(r, byIndex, in.links, in.slots)
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

// hopMask returns the union of the slots of every link r's hops leave through,
// and whether every hop named a link that could be resolved.
func hopMask(
	r *netlink.Route, byIndex map[int]netlink.Link, all []netlink.Link, slots map[uint32]uint8,
) (uint32, bool) {
	hops := make([]int, 0, 1+len(r.MultiPath))
	if len(r.MultiPath) > 0 {
		for _, nh := range r.MultiPath {
			hops = append(hops, nh.LinkIndex)
		}
	} else {
		hops = append(hops, r.LinkIndex)
	}

	var mask uint32
	for _, ifindex := range hops {
		link, ok := byIndex[ifindex]
		if ifindex <= 0 || !ok {
			return 0, false
		}
		for _, idx := range ingressLinks(link, byIndex, all) {
			if slot, ok := slots[uint32(idx)]; ok && int(slot) < MaxSlots {
				mask |= 1 << slot
			}
		}
	}
	return mask, true
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
