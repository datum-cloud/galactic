// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package radv

import (
	"net/netip"
	"testing"
	"time"
)

func TestRateLimited(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		lastSent time.Time
		now      time.Time
		want     bool
	}{
		{"NeverSent", time.Time{}, base, false},
		{"JustSent", base, base.Add(1 * time.Second), true},
		{"ExactlyAtBoundary", base, base.Add(MinDelayBetweenRAs), false},
		{"WellPastBoundary", base, base.Add(MinDelayBetweenRAs + time.Second), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rateLimited(tt.lastSent, tt.now); got != tt.want {
				t.Errorf("rateLimited(%v, %v) = %v, want %v", tt.lastSent, tt.now, got, tt.want)
			}
		})
	}
}

func TestResponseDestination(t *testing.T) {
	guestAddr := netip.MustParseAddr("fe80::1")

	tests := []struct {
		name string
		src  netip.Addr
		want netip.Addr
	}{
		{"UnspecifiedSourceFallsBackToMulticast", netip.IPv6Unspecified(), allNodesMulticast},
		{"UnicastSourceIsUsedDirectly", guestAddr, guestAddr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := responseDestination(tt.src); got != tt.want {
				t.Errorf("responseDestination(%v) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}
