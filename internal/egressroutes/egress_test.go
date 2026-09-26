// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutes

import (
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// TestTenantShardSIDs_WritesTheArgument is the regression test for #538:
// every tenant VRF on a node encapsulated toward a byte-identical shard SID, so
// a shard read one constant Argument for all of them and two same-node tenants
// with overlapping ULAs shared a connection row.
func TestTenantShardSIDs_WritesTheArgument(t *testing.T) {
	sids, err := config.ParseEgressShardSIDs("2001:db8:ff01:9:e001::,2001:db8:ff02:9:e001::")
	if err != nil {
		t.Fatalf("config.ParseEgressShardSIDs() error = %v, want nil", err)
	}

	got, err := TenantShardSIDs(sids, 0x2a5)
	if err != nil {
		t.Fatalf("TenantShardSIDs() error = %v, want nil", err)
	}

	want := []string{"2001:db8:ff01:9:e2a5::", "2001:db8:ff02:9:e2a5::"}
	if len(got) != len(want) {
		t.Fatalf("TenantShardSIDs() = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("TenantShardSIDs()[%d] = %v, want %s", i, got[i], w)
		}
	}
}

// TestTenantShardSIDs_DistinctPerTenant states the property #538 is about
// directly: two VRFIDs on one node must not produce the same destination.
func TestTenantShardSIDs_DistinctPerTenant(t *testing.T) {
	sids, err := config.ParseEgressShardSIDs("2001:db8:ff01:9:e001::")
	if err != nil {
		t.Fatalf("config.ParseEgressShardSIDs() error = %v, want nil", err)
	}

	a, err := TenantShardSIDs(sids, 0x001)
	if err != nil {
		t.Fatalf("TenantShardSIDs(0x001) error = %v, want nil", err)
	}
	b, err := TenantShardSIDs(sids, 0x002)
	if err != nil {
		t.Fatalf("TenantShardSIDs(0x002) error = %v, want nil", err)
	}
	if a[0].Equal(b[0]) {
		t.Errorf("VRFIDs 0x001 and 0x002 both encapsulate toward %v; they must differ", a[0])
	}
}

// TestTenantShardSIDs_OverwritesAConfiguredArgument covers the operator-
// supplied Argument every deployment bakes into its shard SID today. It
// identifies no tenant, one configured value being shared by every VRF on
// every node, so it is replaced, not honoured or treated as a conflict.
func TestTenantShardSIDs_OverwritesAConfiguredArgument(t *testing.T) {
	sids, err := config.ParseEgressShardSIDs("2001:db8:ff01:9:efff::")
	if err != nil {
		t.Fatalf("config.ParseEgressShardSIDs() error = %v, want nil", err)
	}

	got, err := TenantShardSIDs(sids, 0x007)
	if err != nil {
		t.Fatalf("TenantShardSIDs() error = %v, want nil", err)
	}
	if want := "2001:db8:ff01:9:e007::"; got[0].String() != want {
		t.Errorf("TenantShardSIDs() = %v, want %s", got[0], want)
	}
}

// TestTenantShardSIDs_PreservesBlockNodeIDAndFunction guards the fields the
// Argument rewrite must leave alone: get any of them wrong and the packet is
// addressed to a different shard, or to no shard at all.
func TestTenantShardSIDs_PreservesBlockNodeIDAndFunction(t *testing.T) {
	sids, err := config.ParseEgressShardSIDs("2001:db8:ff01:9:e001::")
	if err != nil {
		t.Fatalf("config.ParseEgressShardSIDs() error = %v, want nil", err)
	}

	got, err := TenantShardSIDs(sids, 0x123)
	if err != nil {
		t.Fatalf("TenantShardSIDs() error = %v, want nil", err)
	}
	addr, ok := netip.AddrFromSlice(got[0].To16())
	if !ok {
		t.Fatalf("TenantShardSIDs() returned %v, which is not a 16-byte address", got[0])
	}
	fields, err := uformat.Decode(addr)
	if err != nil {
		t.Fatalf("uformat.Decode(%v) error = %v, want nil", addr, err)
	}
	if fields.Block != 0x2001_0db8_ff01 {
		t.Errorf("Block = %#x, want %#x", fields.Block, 0x2001_0db8_ff01)
	}
	if fields.NodeID != 9 {
		t.Errorf("NodeID = %d, want 9", fields.NodeID)
	}
	if fields.Function != uformat.FunctionEndDT46 {
		t.Errorf("Function = %#x, want %#x", fields.Function, uformat.FunctionEndDT46)
	}
	if fields.Argument != 0x123 {
		t.Errorf("Argument = %#x, want %#x", fields.Argument, 0x123)
	}
}

// TestTenantShardSIDs_RejectsAMalformedSID covers the entries
// config.ParseEgressShardSIDs accepts as valid IP addresses but that are not
// uSIDs. Writing an Argument into one produces a plausible-looking destination
// that addresses nothing, so it fails instead of being passed through.
func TestTenantShardSIDs_RejectsAMalformedSID(t *testing.T) {
	for _, raw := range []string{
		"2001:db8:ff01:9:e001::1", // non-zero padding: not a uFMT 48+16 address
		"192.0.2.1",               // IPv4: not an SRv6 SID at all
	} {
		sids, err := config.ParseEgressShardSIDs(raw)
		if err != nil {
			t.Fatalf("config.ParseEgressShardSIDs(%q) error = %v, want nil", raw, err)
		}
		if _, err := TenantShardSIDs(sids, 0x005); err == nil {
			t.Errorf("TenantShardSIDs(%q) error = nil, want an error", raw)
		}
	}
}

// TestInstall_RefusesAnEmptyShardList pins that a node naming no shard cannot
// hand a VRF a route: the caller decides whether that fails an ADD or is
// logged by a sweep, but nothing is written either way.
func TestInstall_RefusesAnEmptyShardList(t *testing.T) {
	if err := Install(100, 0x005, nil, nil); err == nil {
		t.Error("Install() with no shards = nil, want an error")
	}
}
