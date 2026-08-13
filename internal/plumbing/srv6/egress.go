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
	routes, err := netlink.RouteGet(gateway)
	if err != nil {
		return fmt.Errorf("no route to gateway %s: %w", gateway, err)
	}
	if len(routes) == 0 {
		return fmt.Errorf("no route to gateway %s", gateway)
	}
	encap := &netlink.SEG6Encap{
		Mode:     seg6IptunModeEncapRed,
		Segments: []net.IP{gateway},
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(tableID),
		Encap:     encap,
		LinkIndex: routes[0].LinkIndex,
	}
	if nextHop := routes[0].Gw; len(nextHop) > 0 {
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

// RouteEgressDel removes the SEG6 encap route for prefix from routing table
// tableID.
//
// Deliberately does not set Encap on the delete request the way the
// analogous add/replace path does: RTM_DELROUTE only needs Dst+Table to
// identify which route to remove, but netlink.RouteDel's shared encoding
// path (routeHandle, used by every Route* function regardless of message
// type) still tries to encode whatever Encap is set to, and
// nl.EncodeSEG6Encap unconditionally rejects a SEG6Encap with zero
// Segments — exactly what an empty &netlink.SEG6Encap{} is. Every call to
// this function failed with "EncodeSEG6Encap: No Segment in srh" until
// this fix (datum-cloud/enhancements#865's internal/egressroute is the
// first caller with a test that actually exercises the delete path;
// existing production callers — internal/runtime/gobgp/monitor.go's BGP
// path-withdrawal handler — had none).
func RouteEgressDel(prefix *net.IPNet, tableID uint32) error {
	return netlink.RouteDel(&netlink.Route{
		Dst:   prefix,
		Table: int(tableID),
	})
}
