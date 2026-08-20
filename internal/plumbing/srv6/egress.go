// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// seg6IptunModeEncapRed is SEG6_IPTUN_MODE_ENCAP_RED from the kernel UAPI
// (include/uapi/linux/seg6_iptunnel.h's mode enum: INLINE=0, ENCAP=1,
// L2ENCAP=2, ENCAP_RED=3, L2ENCAP_RED=4). The vendored
// github.com/vishvananda/netlink/nl package only exports INLINE(0)/ENCAP(1)
// -- it has never picked up the kernel's later reduced-mode values -- but
// netlink.SEG6Encap.Mode is a plain int forwarded verbatim to the kernel via
// nl.EncodeSEG6Encap with no validation, so the numeric value can be used
// directly without patching or forking that dependency.
//
// "Reduced" encap matters here because it changes the wire format for the
// single-segment case this function always installs (Segments always has
// exactly one entry, the resolved SID). Confirmed empirically against this
// SID/lab's kernel and iproute2 (ip -6 route add ... encap seg6 mode
// encap.red segs <sid> ..., captured on the wire both for an IPv6 inner
// packet and, matching this codebase's actual IPv4-VPC-over-IPv6-underlay
// case, an IPv4 inner packet): SEG6_IPTUN_MODE_ENCAP (the previous value
// here) always prepends a full Segment Routing Header (RFC 8754, outer
// Next Header = 43/Routing), even for one segment. SEG6_IPTUN_MODE_ENCAP_RED
// omits the SRH entirely for a single segment -- the one segment is already
// fully expressed by the outer destination address, so there is nothing
// left for an SRH to carry -- leaving the outer Next Header set directly to
// the inner packet's own protocol (4/IPIP or 41/IPv6-in-IPv6).
//
// That distinction is why cross-node pod traffic was silently black-holed:
// internal/plumbing/ebpf/prog/usid.c's galactic_usid_ingress TC-BPF program
// (the sole ingress/decap path since the legacy seg6local route model was
// removed) requires the outer Next Header to name the inner packet's AF
// directly (IPIP=4 or IPv6-in-IPv6=41) and unconditionally drops anything
// else -- including a Routing Header -- as DROP_REASON_UNEXPECTED_NEXTHDR.
// Every packet this function's previous SEG6_IPTUN_MODE_ENCAP route
// produced hit exactly that drop on arrival at the destination node.
const seg6IptunModeEncapRed = 3

// RouteEgressAdd installs a SEG6 encap route for prefix into routing table
// tableID, encapsulating to the given SRv6 SID (gateway). The outgoing
// interface and L3 next-hop are resolved from the kernel's routing table for
// gateway so the encapsulated outer packet can be L2-resolved on egress.
//
// gateway must be a real SRv6 SID: an unspecified address (0.0.0.0 or ::,
// including its IPv4-mapped ::ffff:0.0.0.0 form) means the caller never
// resolved a real destination SID — installing it anyway would silently
// blackhole traffic to prefix behind a route to nowhere, which is exactly
// what happened before this check existed (an EVPN path with no usable SID
// attribute was fed straight through). Fail loudly instead.
//
// The resolved next-hop is attached via RTA_VIA (netlink.Route.Via) only
// when prefix's family differs from the next-hop's — SRv6 SIDs are
// IPv6-only in this architecture, so that's exactly the IPv4 VPC prefix
// case (egressing over an IPv6 SRv6 underlay), where the plain Gw field
// can't be used: Gw requires its address to share Dst's family and the
// kernel rejects the mismatch outright, while Via carries a next-hop of a
// different family than Dst by design.
//
// For an IPv6 VPC prefix, though, the next-hop already shares Dst's family,
// and Via must NOT be used: unlike iproute2's `via` keyword, which silently
// downgrades to a plain RTA_GATEWAY whenever the given address turns out to
// share Dst's family, this netlink library sends whatever attribute the
// caller set verbatim — RTA_VIA with a same-family address is rejected by
// the kernel with EINVAL. Confirmed empirically: this function unconditionally
// using Via previously blackholed every IPv6 VPC prefix's egress route
// (RouteEgressAdd failing with "invalid argument"), while the IPv4 case,
// which does need Via, worked fine.
func RouteEgressAdd(prefix *net.IPNet, gateway net.IP, tableID uint32) error {
	if gateway == nil || gateway.IsUnspecified() {
		return fmt.Errorf("refusing to install seg6 encap route for %s: gateway %s is not a usable SRv6 SID", prefix, gateway)
	}
	linkIndex, nextHop, err := resolveNextHop(gateway)
	if err != nil {
		return err
	}
	encap := &netlink.SEG6Encap{
		Mode:     seg6IptunModeEncapRed,
		Segments: []net.IP{gateway},
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(tableID),
		Encap:     encap,
		LinkIndex: linkIndex,
	}
	if len(nextHop) > 0 {
		if prefix.IP.To4() != nil {
			// IPv4 VPC prefix, IPv6 next-hop: cross-family, must use Via.
			route.Via = &netlink.Via{AddrFamily: netlink.FAMILY_V6, Addr: nextHop}
		} else {
			// IPv6 VPC prefix: next-hop shares Dst's family, use Gw.
			route.Gw = nextHop
		}
	}
	return netlink.RouteReplace(route)
}

// resolveNextHop resolves gateway's real, immediate next-hop -- the exact
// link plus (unless gateway is itself on-link) the concrete address the
// kernel would actually forward through right now -- via netlink.RouteGet.
//
// This flattening matters because IPv6 route installation does not recurse
// through an indirect gateway on its own: passing gateway straight through
// as a route's Gw with no LinkIndex set fails with "no route to host"
// whenever gateway is only reachable via its own separate route (e.g.
// through a link-local next-hop) rather than being on-link itself --
// confirmed empirically live in containerlab, where every BGP next-hop
// used as a plain gateway (RouteMainAdd, below) is exactly this indirect
// shape. Both RouteEgressAdd and RouteMainAdd need gateway flattened into
// one concrete hop before installing anything, for the same reason.
func resolveNextHop(gateway net.IP) (linkIndex int, nextHop net.IP, err error) {
	routes, err := netlink.RouteGet(gateway)
	if err != nil {
		return 0, nil, fmt.Errorf("no route to gateway %s: %w", gateway, err)
	}
	if len(routes) == 0 {
		return 0, nil, fmt.Errorf("no route to gateway %s", gateway)
	}
	return routes[0].LinkIndex, routes[0].Gw, nil
}

// RouteEgressDel removes the SEG6 encap route for prefix from routing table tableID.
func RouteEgressDel(prefix *net.IPNet, tableID uint32) error {
	return netlink.RouteDel(&netlink.Route{
		Dst:   prefix,
		Table: int(tableID),
		Encap: &netlink.SEG6Encap{},
	})
}

// RouteMainAdd installs a plain route for prefix in routing table tableID,
// forwarding to gateway via ordinary recursive next-hop resolution -- no
// SEG6 encapsulation, unlike RouteEgressAdd.
//
// This exists for EVPN Type 5 paths that carry no Route Target extended
// community at all (see matchTableID in internal/runtime/gobgp/monitor.go):
// NetworkGatewayReconciler's anycast ingress-VIP advertisements are the one
// case today, deliberately left VRFID/Function-less because they name no
// tenant VRF (that reconciler's own package doc comment). Their EVPN path
// therefore carries no Prefix-SID either, so gateway here is always the
// path's plain BGP next-hop -- a real, already fabric-reachable node
// address (how else could this path's own BGP session exist), not a uSID
// decap SID. Wrapping the packet in another SEG6/IPv6-in-IPv6 header toward
// that address the way RouteEgressAdd does for a tenant VRF prefix would
// only make it undeliverable: nothing there is listening for that
// encapsulation the way usid_ingress listens for a real uSID SID's traffic.
// Ordinary recursive forwarding is what an anycast route actually needs.
//
// gateway must be a real address for the same reason RouteEgressAdd
// requires one: an unspecified gateway would silently blackhole prefix
// behind a route to nowhere.
func RouteMainAdd(prefix *net.IPNet, gateway net.IP, tableID uint32) error {
	if gateway == nil || gateway.IsUnspecified() {
		return fmt.Errorf("refusing to install route for %s: gateway %s is not a usable next-hop", prefix, gateway)
	}
	linkIndex, nextHop, err := resolveNextHop(gateway)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(tableID),
		LinkIndex: linkIndex,
	}
	if len(nextHop) > 0 {
		if prefix.IP.To4() != nil {
			route.Via = &netlink.Via{AddrFamily: netlink.FAMILY_V6, Addr: nextHop}
		} else {
			route.Gw = nextHop
		}
	} else {
		// gateway itself is on-link (RouteGet found no further next-hop of
		// its own) -- unlike RouteEgressAdd's SEG6 encap case, where the
		// segment list alone already fully specifies the destination, a
		// plain route needs an explicit gateway here or the kernel would
		// treat prefix itself as directly reachable on this link.
		route.Gw = gateway
	}
	return netlink.RouteReplace(route)
}

// RouteMainDel removes the plain route for prefix from routing table
// tableID -- RouteMainAdd's counterpart, mirroring RouteEgressDel.
func RouteMainDel(prefix *net.IPNet, tableID uint32) error {
	return netlink.RouteDel(&netlink.Route{
		Dst:   prefix,
		Table: int(tableID),
	})
}
