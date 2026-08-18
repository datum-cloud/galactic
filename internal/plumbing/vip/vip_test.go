// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// This package has no CAP_NET_ADMIN-requiring unit tests -- like
// internal/plumbing/vrf, that requires a real kernel and should be covered
// by e2e/containerlab validation instead (see CONVENTIONS.md's "What not
// to test"). Only hostNet's pure address-to-CIDR logic is covered here.
package vip

import (
	"net"
	"testing"
)

func TestHostNet(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantCIDR string
	}{
		{"IPv4", "203.0.113.5", "203.0.113.5/32"},
		{"IPv6", "2001:db8::1", "2001:db8::1/128"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostNet(net.ParseIP(tt.addr))
			if got.String() != tt.wantCIDR {
				t.Errorf("hostNet(%s) = %s, want %s", tt.addr, got.String(), tt.wantCIDR)
			}
		})
	}
}
