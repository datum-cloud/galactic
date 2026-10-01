// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostgw

import (
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/vrf"
)

// requireRoot skips the test when not running as root.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root")
	}
}

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return ipnet
}

func TestIPv4GatewayAddrParams(t *testing.T) {
	tests := []struct {
		name      string
		hostLink  netlink.Link
		wantMask  net.IPMask
		wantFlags int
	}{
		{
			name:      "tap gets /25 with NOPREFIXROUTE",
			hostLink:  &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "tap0"}},
			wantMask:  net.CIDRMask(25, 32),
			wantFlags: unix.IFA_F_NOPREFIXROUTE,
		},
		{
			name:      "veth gets /32 with no flags",
			hostLink:  &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth0"}},
			wantMask:  net.CIDRMask(32, 32),
			wantFlags: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMask, gotFlags := ipv4GatewayAddrParams(tt.hostLink)
			if gotMask.String() != tt.wantMask.String() {
				t.Errorf("mask = %v, want %v", gotMask, tt.wantMask)
			}
			if gotFlags != tt.wantFlags {
				t.Errorf("flags = %v, want %v", gotFlags, tt.wantFlags)
			}
		})
	}
}

func TestRouteConflicts(t *testing.T) {
	dst := mustParseCIDR(t, "fd00:10:ff01::1234/80")
	gw1 := net.ParseIP("fd00:10:ff01::1")
	gw2 := net.ParseIP("fd00:10:ff01::2")
	otherDst := mustParseCIDR(t, "fd00:10:ff02::1234/80")

	tests := []struct {
		name     string
		existing *netlink.Route
		desired  *netlink.Route
		want     bool
	}{
		{"nil existing destination — no conflict", &netlink.Route{Dst: nil}, &netlink.Route{Dst: dst}, false},
		{"nil desired destination — no conflict", &netlink.Route{Dst: dst}, &netlink.Route{Dst: nil}, false},
		{"different destinations — no conflict", &netlink.Route{Dst: otherDst}, &netlink.Route{Dst: dst}, false},
		{
			"same destination, no gateway on either — no conflict",
			&netlink.Route{Dst: dst, LinkIndex: 5}, &netlink.Route{Dst: dst, LinkIndex: 5}, false,
		},
		{
			"same destination, same gateway — no conflict",
			&netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5}, &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5}, false,
		},
		{
			"same destination, different gateway — conflict",
			&netlink.Route{Dst: dst, Gw: gw1}, &netlink.Route{Dst: dst, Gw: gw2}, true,
		},
		{
			"existing has gateway, desired does not — conflict",
			&netlink.Route{Dst: dst, Gw: gw1}, &netlink.Route{Dst: dst}, true,
		},
		{
			"desired has gateway, existing does not — conflict",
			&netlink.Route{Dst: dst}, &netlink.Route{Dst: dst, Gw: gw1}, true,
		},
		{
			"same destination, same gateway, different link index — conflict",
			&netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5}, &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 7}, true,
		},
		{
			"same destination, gateway set, link index zero on existing — no conflict",
			&netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 0}, &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5}, false,
		},
		{
			"same destination, no gateway, different link index — conflict",
			&netlink.Route{Dst: dst, LinkIndex: 5}, &netlink.Route{Dst: dst, LinkIndex: 7}, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routeConflicts(tt.existing, tt.desired)
			if got != tt.want {
				t.Errorf("routeConflicts() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestInstallPodSubnetRouteReplacesStaleRoute models the tap-reuse scenario
// that let a stale route survive a container replacement: a host device
// carries a route from a previous container's subnet, kept only because
// installPodSubnetRoute used to check for a matching destination and never
// for a matching interface. It must remove that route and install the new
// container's, and must leave alone a route in the same table that belongs
// to a different interface entirely, as well as the kernel's own routes on
// this device -- removing its multicast ff00::/8 left containers unable to
// resolve their gateway at all.
func TestInstallPodSubnetRouteReplacesStaleRoute(t *testing.T) {
	requireRoot(t)

	const tableID = 250

	ownLink := addDummyLink(t, "hgwtestown0")
	otherLink := addDummyLink(t, "hgwtestoth0")

	staleSubnet := mustParseCIDR(t, "fd00:aa:bb::1/96")
	desiredSubnet := mustParseCIDR(t, "fd00:aa:cc::1/96")
	otherSubnet := mustParseCIDR(t, "fd00:aa:dd::1/96")

	// A route left behind on this device by a previous container's attachment.
	if err := netlink.RouteAdd(&netlink.Route{
		Dst: staleSubnet, LinkIndex: ownLink.Attrs().Index, Table: tableID,
	}); err != nil {
		t.Fatalf("seed stale route: %v", err)
	}
	// A route in the same table but on a different interface, standing in for
	// a sibling attachment's own subnet route that must not be touched.
	if err := netlink.RouteAdd(&netlink.Route{
		Dst: otherSubnet, LinkIndex: otherLink.Attrs().Index, Table: tableID,
	}); err != nil {
		t.Fatalf("seed sibling route: %v", err)
	}

	// The kernel's own routes on this device, as it installs them for a VRF
	// slave: a link-local unicast route and the multicast route NDP needs.
	kernelLinkLocal := mustParseCIDR(t, "fe80::/64")
	kernelMulticast := mustParseCIDR(t, "ff00::/8")
	for _, r := range []*netlink.Route{
		{Dst: kernelLinkLocal, LinkIndex: ownLink.Attrs().Index, Table: tableID, Protocol: unix.RTPROT_KERNEL},
		{
			Dst: kernelMulticast, LinkIndex: ownLink.Attrs().Index, Table: tableID,
			Protocol: unix.RTPROT_KERNEL, Type: unix.RTN_MULTICAST,
		},
	} {
		if err := netlink.RouteAdd(r); err != nil {
			t.Fatalf("seed kernel route %s: %v", r.Dst, err)
		}
	}

	if err := installPodSubnetRoute(ownLink, desiredSubnet, netlink.FAMILY_V6, tableID); err != nil {
		t.Fatalf("installPodSubnetRoute: %v", err)
	}

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("list routes: %v", err)
	}
	have := map[string]bool{}
	for _, r := range routes {
		if r.Dst != nil {
			have[r.Dst.String()] = true
		}
	}
	if have[staleSubnet.String()] {
		t.Errorf("stale route %s still present, want removed", staleSubnet)
	}
	if !have[desiredSubnet.String()] {
		t.Errorf("desired route %s not installed", desiredSubnet)
	}
	if !have[otherSubnet.String()] {
		t.Errorf("sibling route %s on another interface was removed, want left alone", otherSubnet)
	}
	for _, kernel := range []*net.IPNet{kernelLinkLocal, kernelMulticast} {
		if !have[kernel.String()] {
			t.Errorf("kernel route %s on this device was removed, want left alone", kernel)
		}
	}
}

// TestIsPodSubnetRouteCandidate_SparesUnreachableDefault covers the route
// vrf.Add puts in every VRF table to stop tenant traffic falling through to
// the main table. The stale-route sweep must never treat it as a pod-subnet
// route, or the next ADD on an adopted device would reopen that leak.
func TestIsPodSubnetRouteCandidate_SparesUnreachableDefault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route netlink.Route
		want  bool
	}{
		{"a pod-subnet route", netlink.Route{Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_BOOT}, true},
		{"an unreachable default", netlink.Route{Type: unix.RTN_UNREACHABLE, Protocol: unix.RTPROT_BOOT}, false},
		{"a blackhole", netlink.Route{Type: unix.RTN_BLACKHOLE, Protocol: unix.RTPROT_BOOT}, false},
		{"a kernel unicast route", netlink.Route{Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_KERNEL}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPodSubnetRouteCandidate(&tc.route); got != tc.want {
				t.Errorf("isPodSubnetRouteCandidate(type %d, proto %d) = %v, want %v",
					tc.route.Type, tc.route.Protocol, got, tc.want)
			}
		})
	}
}

// TestInstallPodSubnetRouteKeepsUnreachableDefault runs the real sweep against
// a table holding vrf.Add's unreachable defaults and checks both survive.
func TestInstallPodSubnetRouteKeepsUnreachableDefault(t *testing.T) {
	requireRoot(t)

	const tableID = 251
	const metric = vrf.UnreachableDefaultMetric

	ownLink := addDummyLink(t, "hgwtestunr0")
	defaults := []struct {
		family int
		dst    *net.IPNet
	}{
		{netlink.FAMILY_V4, mustParseCIDR(t, "0.0.0.0/0")},
		{netlink.FAMILY_V6, mustParseCIDR(t, "::/0")},
	}
	for _, d := range defaults {
		r := &netlink.Route{Dst: d.dst, Table: tableID, Type: unix.RTN_UNREACHABLE, Priority: metric}
		if err := netlink.RouteAdd(r); err != nil {
			t.Fatalf("seed unreachable default %s: %v", d.dst, err)
		}
		t.Cleanup(func() { _ = netlink.RouteDel(r) })
	}

	for _, sub := range []struct {
		cidr   string
		family int
	}{
		{"fd00:aa:ee::1/96", netlink.FAMILY_V6},
		{"10.250.0.0/24", netlink.FAMILY_V4},
	} {
		if err := installPodSubnetRoute(ownLink, mustParseCIDR(t, sub.cidr), sub.family, tableID); err != nil {
			t.Fatalf("installPodSubnetRoute %s: %v", sub.cidr, err)
		}
	}

	for _, d := range defaults {
		routes, err := netlink.RouteListFiltered(d.family, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatalf("list routes: %v", err)
		}
		found := false
		for _, r := range routes {
			if r.Type == unix.RTN_UNREACHABLE && r.Priority == metric {
				found = true
			}
		}
		if !found {
			t.Errorf("unreachable default %s was removed by the pod-subnet sweep, want left alone", d.dst)
		}
	}
}

// addDummyLink creates an up dummy link named name, cleaned up at test end.
func addDummyLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		t.Fatalf("create dummy link %q: %v", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("find dummy link %q: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring up dummy link %q: %v", name, err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	return link
}
