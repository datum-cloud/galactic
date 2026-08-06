// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

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
// The resolved next-hop is attached via RTA_VIA (netlink.Route.Via), not the
// plain Gw field. SRv6 SIDs are IPv6-only in this architecture, but prefix —
// the inner destination being matched — can be IPv4 (an IPv4 VPC prefix
// egressing over an IPv6 SRv6 underlay). Gw requires its address to share
// Dst's family and the kernel rejects the mismatch outright; Via carries a
// next-hop of a different family than Dst by design, which is exactly this
// case: an IPv4 route whose next-hop is only reachable over an IPv6 link.
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
		Mode:     nl.SEG6_IPTUN_MODE_ENCAP,
		Segments: []net.IP{gateway},
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(tableID),
		Encap:     encap,
		LinkIndex: routes[0].LinkIndex,
	}
	if len(routes[0].Gw) > 0 {
		route.Via = &netlink.Via{AddrFamily: netlink.FAMILY_V6, Addr: routes[0].Gw}
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
