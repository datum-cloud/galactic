// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// seg6IptunModeEncapRed is the kernel's SEG6_IPTUN_MODE_ENCAP_RED
// (include/uapi/linux/seg6_iptunnel.h) -- "reduced" encapsulation, which
// omits the Segment Routing Header entirely when the segment list has only
// one entry (our uSID case, always a single compressed SID). The
// vishvananda/netlink version pinned in go.mod only exposes
// SEG6_IPTUN_MODE_INLINE/_ENCAP (nl.SEG6_IPTUN_MODE_ENCAP, plain "full"
// encap, always adds an 8+16-byte Routing Header even for one segment) --
// there is no library constant for this mode, but SEG6Encap.Mode is a plain
// int with no validation, so the raw kernel value works unchanged.
// usid.c's ingress decap strips exactly sizeof(struct usid_ip6hdr) (40
// bytes, the outer IPv6 header alone) with no allowance for a Routing
// Header; installing routes in "full encap" mode put a live 24-byte SRH
// between that stripped header and the inner packet, so decap
// misidentified the SRH's first byte as the inner IP version and every
// cross-region uSID packet was dropped (DROP_REASON_UNKNOWN_INNER_VERSION)
// -- confirmed live via the datapath's own drops_total metric before this
// fix, and by byte-for-byte comparing tcpdump's outer-packet capture
// (RT6 Routing Header, type 4) against usid.c's step 7 strip width.
const seg6IptunModeEncapRed = 3

// RouteEgressAdd installs a SEG6 encap route for prefix into routing table
// tableID, encapsulating to the given SRv6 SID (gateway). The outgoing
// interface and L3 next-hop are resolved from the kernel's routing table for
// gateway so the encapsulated outer packet can be L2-resolved on egress.
//
// The SID is always an IPv6 address (RFC 9252), but prefix may be an IPv4
// VPC subnet (End.DT46) — so the resolved next-hop's family can differ from
// prefix's. netlink.Route.Gw requires the same family as Dst (the kernel
// route message carries one address family for the whole route); a
// different-family next-hop must instead go through RTA_VIA, which
// netlink.Route exposes as the Via field.
func RouteEgressAdd(prefix *net.IPNet, gateway net.IP, tableID uint32) error {
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
	gw := routes[0].Gw
	gwFamily := netlink.FAMILY_V6
	if gw.To4() != nil {
		gwFamily = netlink.FAMILY_V4
	}
	if (prefix.IP.To4() != nil) == (gwFamily == netlink.FAMILY_V4) {
		route.Gw = gw
	} else {
		route.Via = &netlink.Via{AddrFamily: gwFamily, Addr: gw}
	}
	return netlink.RouteReplace(route)
}

// RouteEgressDel removes the SEG6 encap route for prefix from routing table tableID.
func RouteEgressDel(prefix *net.IPNet, tableID uint32) error {
	return netlink.RouteDel(&netlink.Route{
		Dst:   prefix,
		Table: int(tableID),
		Encap: &netlink.SEG6Encap{},
	})
}
