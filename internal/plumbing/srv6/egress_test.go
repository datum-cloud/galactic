// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

// requireRoot skips the test unless running as root (CAP_NET_ADMIN to
// install/remove a real kernel route) -- same pattern used throughout this
// codebase (e.g. internal/plumbing/ebpf/prog/usid_test.go's requireRoot).
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to install/remove a real kernel route; re-run via sudo")
	}
}

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

// TestCheckSEG6EncapRed exercises CheckSEG6EncapRed against the real
// running kernel: on a kernel new enough for SEG6_IPTUN_MODE_ENCAP_RED
// (this environment is documented to have one), it must return nil, and
// must leave no trace of its scratch probe route behind afterward -- the
// same "attempt it for real, prove it cleans up" bar
// internal/plumbing/ebpf/preflight's own kernel-capability probes hold
// themselves to.
func TestCheckSEG6EncapRed(t *testing.T) {
	requireRoot(t)

	if err := CheckSEG6EncapRed(); err != nil {
		t.Fatalf("CheckSEG6EncapRed() = %v, want nil (this environment is documented to support "+
			"SEG6_IPTUN_MODE_ENCAP_RED)", err)
	}

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
		Table: checkSEG6EncapRedTableID,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("list routes in scratch table %#x: %v", checkSEG6EncapRedTableID, err)
	}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == checkSEG6EncapRedDst.String() {
			t.Errorf("scratch probe route %s still present in table %#x after CheckSEG6EncapRed returned",
				r.Dst, checkSEG6EncapRedTableID)
		}
	}
}

// TestCheckSEG6EncapRed_Idempotent covers calling CheckSEG6EncapRed twice
// in a row -- RouteEgressAdd's own production call sites hit RouteReplace
// repeatedly by design (backfillEVPNRoutes' doc comment calls re-applying
// an already-installed route "a harmless no-op"), so this probe must
// tolerate the same on its own scratch route.
func TestCheckSEG6EncapRed_Idempotent(t *testing.T) {
	requireRoot(t)

	if err := CheckSEG6EncapRed(); err != nil {
		t.Fatalf("first CheckSEG6EncapRed() = %v, want nil", err)
	}
	if err := CheckSEG6EncapRed(); err != nil {
		t.Fatalf("second CheckSEG6EncapRed() = %v, want nil", err)
	}
}
