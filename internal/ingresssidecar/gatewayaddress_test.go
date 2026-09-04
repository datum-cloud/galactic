// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"net"
	"testing"
)

func mustParseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("net.ParseCIDR(%q): %v", s, err)
	}
	return network
}

func TestDeriveGatewayAddress_Deterministic(t *testing.T) {
	prefix := mustParseCIDR(t, "fd00:6741:7761::/48")

	got1, err := DeriveGatewayAddress(prefix, "2", "worker-1")
	if err != nil {
		t.Fatalf("DeriveGatewayAddress: %v", err)
	}
	got2, err := DeriveGatewayAddress(prefix, "2", "worker-1")
	if err != nil {
		t.Fatalf("DeriveGatewayAddress (second call): %v", err)
	}
	if !got1.Equal(got2) {
		t.Errorf("DeriveGatewayAddress is not deterministic: %v != %v", got1, got2)
	}
}

func TestDeriveGatewayAddress_WithinPrefix(t *testing.T) {
	prefix := mustParseCIDR(t, "fd00:6741:7761::/48")
	addr, err := DeriveGatewayAddress(prefix, "2", "worker-1")
	if err != nil {
		t.Fatalf("DeriveGatewayAddress: %v", err)
	}
	if !prefix.Contains(addr) {
		t.Errorf("derived address %v is not contained in prefix %v", addr, prefix)
	}
}

func TestDeriveGatewayAddress_DiffersByVPCAndNode(t *testing.T) {
	prefix := mustParseCIDR(t, "fd00:6741:7761::/48")

	base, err := DeriveGatewayAddress(prefix, "2", "worker-1")
	if err != nil {
		t.Fatalf("DeriveGatewayAddress: %v", err)
	}

	otherVPC, err := DeriveGatewayAddress(prefix, "70", "worker-1")
	if err != nil {
		t.Fatalf("DeriveGatewayAddress (other vpc): %v", err)
	}
	if base.Equal(otherVPC) {
		t.Error("different VPCs derived the same gateway address")
	}

	otherNode, err := DeriveGatewayAddress(prefix, "2", "worker-2")
	if err != nil {
		t.Fatalf("DeriveGatewayAddress (other node): %v", err)
	}
	if base.Equal(otherNode) {
		t.Error("different nodes derived the same gateway address for the same VPC")
	}
}

func TestDeriveGatewayAddress_RejectsNonByteAlignedPrefix(t *testing.T) {
	prefix := mustParseCIDR(t, "fd00:6741:7761::/50") // not a multiple of 8
	if _, err := DeriveGatewayAddress(prefix, "2", "worker-1"); err == nil {
		t.Fatal("expected an error for a non-byte-aligned prefix, got nil")
	}
}

func TestDeriveGatewayAddress_RejectsIPv4Prefix(t *testing.T) {
	_, v4prefix, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("net.ParseCIDR: %v", err)
	}
	if _, err := DeriveGatewayAddress(v4prefix, "2", "worker-1"); err == nil {
		t.Fatal("expected an error for an IPv4 prefix, got nil")
	}
}

func TestDeriveGatewayAddress_RejectsHostPrefix(t *testing.T) {
	prefix := mustParseCIDR(t, "fd00:6741:7761::1/128") // no host bits left
	if _, err := DeriveGatewayAddress(prefix, "2", "worker-1"); err == nil {
		t.Fatal("expected an error for a /128 prefix (no host bits), got nil")
	}
}

func TestDeriveGatewayAddress_RejectsInvalidVPC(t *testing.T) {
	prefix := mustParseCIDR(t, "fd00:6741:7761::/48")
	if _, err := DeriveGatewayAddress(prefix, "!!!", "worker-1"); err == nil {
		t.Fatal("expected an error for a non-base62 vpc, got nil")
	}
}

func TestDeriveGatewayAddress_RejectsNilPrefix(t *testing.T) {
	if _, err := DeriveGatewayAddress(nil, "2", "worker-1"); err == nil {
		t.Fatal("expected an error for a nil prefix, got nil")
	}
}

func TestGatewayAddressAssignment_DefaultDisabled(t *testing.T) {
	prefix, nodeID := gatewayAddressAssignment()
	if prefix != nil {
		t.Errorf("gatewayAddressAssignment() prefix = %v, want nil by default", prefix)
	}
	if nodeID != "" {
		t.Errorf("gatewayAddressAssignment() nodeID = %q, want empty by default", nodeID)
	}
}

func TestSetGatewayAddressAssignment_RoundTrips(t *testing.T) {
	t.Cleanup(func() { SetGatewayAddressAssignment(nil, "") })

	prefix := mustParseCIDR(t, "fd00:6741:7761::/48")
	SetGatewayAddressAssignment(prefix, "worker-1")

	gotPrefix, gotNodeID := gatewayAddressAssignment()
	if gotPrefix.String() != prefix.String() {
		t.Errorf("gatewayAddressAssignment() prefix = %v, want %v", gotPrefix, prefix)
	}
	if gotNodeID != "worker-1" {
		t.Errorf("gatewayAddressAssignment() nodeID = %q, want worker-1", gotNodeID)
	}

	SetGatewayAddressAssignment(nil, "")
	gotPrefix, gotNodeID = gatewayAddressAssignment()
	if gotPrefix != nil || gotNodeID != "" {
		t.Errorf("gatewayAddressAssignment() after reset = (%v, %q), want (nil, \"\")", gotPrefix, gotNodeID)
	}
}

// TestEnsureGatewayAddress_NoopWhenDisabled verifies ensureGatewayAddress
// doesn't attempt any netlink call at all (which would fail without
// CAP_NET_ADMIN / a real interface) when address assignment isn't
// configured -- the default state, and the only path exercised outside a
// root-gated integration test.
func TestEnsureGatewayAddress_NoopWhenDisabled(t *testing.T) {
	t.Cleanup(func() { SetGatewayAddressAssignment(nil, "") })
	SetGatewayAddressAssignment(nil, "")

	if err := ensureGatewayAddress("2", "does-not-exist"); err != nil {
		t.Errorf("ensureGatewayAddress with assignment disabled: %v, want nil (no-op)", err)
	}
}

// TestEnsureGatewayVRFRoute_AbsentVRFIsAnError pins that this reports a
// missing VRF rather than silently skipping. The route is what makes the
// gateway address receivable from outside the VRF, so a caller that treated
// its absence as success would leave an address assigned, advertised into
// EVPN, and undeliverable -- the exact failure this route exists to fix,
// but harder to find because nothing would say so.
func TestEnsureGatewayVRFRoute_AbsentVRFIsAnError(t *testing.T) {
	// A VPC with no VRF interface in this test's namespace.
	if err := ensureGatewayVRFRoute("zzzzz", net.ParseIP("fd30:e2e:3a5::1")); err == nil {
		t.Error("ensureGatewayVRFRoute() error = nil, want an error when the VPC has no VRF")
	}
}
