// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"net"
	"testing"
)

// TestRouteEgressAddRejectsUnspecifiedGateway verifies that RouteEgressAdd
// refuses to install a seg6 encap route when it isn't handed a real SRv6 SID.
// This is the defense-in-depth backstop for the bug where a missing/zero SID
// upstream (e.g. an EVPN path with no Prefix-SID attribute) got fed straight
// through and silently installed a route encapsulating to
// "::ffff:0.0.0.0" — a route to nowhere — instead of failing loudly. The
// check must run before any netlink call so this test needs no privileges.
func TestRouteEgressAddRejectsUnspecifiedGateway(t *testing.T) {
	_, prefix, err := net.ParseCIDR("172.20.20.2/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	tests := []struct {
		name    string
		gateway net.IP
	}{
		{name: "nil gateway", gateway: nil},
		{name: "IPv4 zero", gateway: net.IPv4zero},
		{name: "IPv4-mapped IPv6 zero (::ffff:0.0.0.0)", gateway: net.ParseIP("0.0.0.0").To16()},
		{name: "IPv6 zero", gateway: net.IPv6unspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := RouteEgressAdd(prefix, tt.gateway, 1); err == nil {
				t.Errorf("RouteEgressAdd(%v) = nil error, want an error rejecting the unusable gateway", tt.gateway)
			}
		})
	}
}
