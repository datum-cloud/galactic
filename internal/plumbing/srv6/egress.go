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
// gateway must be a real SRv6 SID: an unspecified address (0.0.0.0 or ::,
// including its IPv4-mapped ::ffff:0.0.0.0 form) means the caller never
// resolved a real destination SID — installing it anyway would silently
// blackhole traffic to prefix behind a route to nowhere, which is exactly
// what happened before this check existed (an EVPN path with no usable SID
// attribute was fed straight through). Fail loudly instead.
//
// The SID is always an IPv6 address (RFC 9252), but prefix may be an IPv4
// VPC subnet (End.DT46) — so the resolved next-hop's family can differ from
// prefix's. netlink.Route.Gw requires the same family as Dst (the kernel
// route message carries one address family for the whole route); a
// different-family next-hop must instead go through RTA_VIA, which
// netlink.Route exposes as the Via field.
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
	if gw := routes[0].Gw; len(gw) > 0 {
		gwFamily := netlink.FAMILY_V6
		if gw.To4() != nil {
			gwFamily = netlink.FAMILY_V4
		}
		if (prefix.IP.To4() != nil) == (gwFamily == netlink.FAMILY_V4) {
			route.Gw = gw
		} else {
			route.Via = &netlink.Via{AddrFamily: gwFamily, Addr: gw}
		}
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

// checkSEG6EncapRedTableID and checkSEG6EncapRedDst are CheckSEG6EncapRed's
// scratch route: a table ID and destination chosen to be as far as
// possible from anything a real VRF or route could ever use.
// RouteEgressAdd's own tableIDs come from vrf.TableID (kernel-assigned per
// VRF device at creation, typically a small integer); checkSEG6EncapRedDst
// sits inside RFC 3849's documentation-only IPv6 range, never a real
// destination any route table would legitimately hold. So even in the
// astronomically unlikely case of a table-ID collision, this only ever
// adds, then immediately removes, one inert, unreachable route -- it never
// touches anything a real VRF's forwarding depends on.
var (
	checkSEG6EncapRedTableID = 0xFFFFFFF0
	checkSEG6EncapRedDst     = &net.IPNet{IP: net.ParseIP("2001:db8:ffff:ffff::1"), Mask: net.CIDRMask(128, 128)}
	checkSEG6EncapRedSeg     = net.ParseIP("::1")
)

// CheckSEG6EncapRed probes whether the running kernel's SEG6 iptunnel
// implementation actually supports SEG6_IPTUN_MODE_ENCAP_RED (see
// seg6IptunModeEncapRed's doc comment above for why RouteEgressAdd depends
// on this mode specifically, not plain full encap) by installing, then
// immediately removing, a real route using that exact mode against the
// loopback interface -- the same "attempt it for real" idiom
// internal/plumbing/ebpf/preflight uses for its own kernel-capability
// probes, since SEG6 encap modes are a netlink LWT-encapsulation
// attribute, not something kernel BTF describes the way eBPF helper
// support is.
//
// A kernel too old for reduced encap doesn't reject this any differently
// from any other route-install failure -- RouteEgressAdd itself would fail
// identically and silently for every single cross-region EVPN path this
// router ever tries to install (internal/runtime/gobgp/monitor.go logs
// each failure once, but never retries or otherwise surfaces it as a
// standing, actionable signal). Calling this once at startup turns that
// into one clear, node-level diagnostic instead.
func CheckSEG6EncapRed() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("check SEG6 reduced-encap support: look up loopback interface: %w", err)
	}

	route := &netlink.Route{
		Dst:       checkSEG6EncapRedDst,
		Table:     checkSEG6EncapRedTableID,
		LinkIndex: lo.Attrs().Index,
		Encap: &netlink.SEG6Encap{
			Mode:     seg6IptunModeEncapRed,
			Segments: []net.IP{checkSEG6EncapRedSeg},
		},
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf(
			"kernel rejected a SEG6_IPTUN_MODE_ENCAP_RED route -- RouteEgressAdd depends on this mode "+
				"for every cross-region uSID path (see egress.go's seg6IptunModeEncapRed doc comment): %w", err)
	}

	// Best-effort cleanup: the capability itself was already proven by the
	// successful RouteReplace above, so a failure here doesn't change this
	// check's verdict -- it just leaves one harmless scratch route behind
	// in a table ID nothing else uses (see the doc comment above).
	_ = netlink.RouteDel(route)

	return nil
}
