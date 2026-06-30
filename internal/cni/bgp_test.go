// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// ---- routeConflicts ------------------------------------------------------

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
		{
			name:     "nil existing destination — no conflict",
			existing: &netlink.Route{Dst: nil},
			desired:  &netlink.Route{Dst: dst},
			want:     false,
		},
		{
			name:     "nil desired destination — no conflict",
			existing: &netlink.Route{Dst: dst},
			desired:  &netlink.Route{Dst: nil},
			want:     false,
		},
		{
			name:     "different destinations — no conflict",
			existing: &netlink.Route{Dst: otherDst},
			desired:  &netlink.Route{Dst: dst},
			want:     false,
		},
		{
			name:     "same destination, no gateway on either — no conflict",
			existing: &netlink.Route{Dst: dst, LinkIndex: 5},
			desired:  &netlink.Route{Dst: dst, LinkIndex: 5},
			want:     false,
		},
		{
			name:     "same destination, same gateway — no conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5},
			desired:  &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5},
			want:     false,
		},
		{
			name:     "same destination, different gateway — conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1},
			desired:  &netlink.Route{Dst: dst, Gw: gw2},
			want:     true,
		},
		{
			name:     "existing has gateway, desired does not — conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1},
			desired:  &netlink.Route{Dst: dst},
			want:     true,
		},
		{
			name:     "desired has gateway, existing does not — conflict",
			existing: &netlink.Route{Dst: dst},
			desired:  &netlink.Route{Dst: dst, Gw: gw1},
			want:     true,
		},
		{
			name:     "same destination, same gateway, different link index — conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5},
			desired:  &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 7},
			want:     true,
		},
		{
			name:     "same destination, gateway set, link index zero on existing — no conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 0},
			desired:  &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5},
			want:     false,
		},
		{
			name:     "same destination, no gateway, different link index — conflict",
			existing: &netlink.Route{Dst: dst, LinkIndex: 5},
			desired:  &netlink.Route{Dst: dst, LinkIndex: 7},
			want:     true,
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
