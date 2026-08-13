// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostgw

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

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
