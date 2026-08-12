// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"net/netip"
	"testing"
)

// Shared test rule keys, used across this file and telemetry_test.go.
const (
	testRuleKeyR1 = "ns/r1"
	testRuleKeyR2 = "ns/r2"
)

func testRuleWithVIPs(key, vpcRef string, vipCount int) DesiredRule {
	vips := make([]netip.Addr, vipCount)
	for i := range vips {
		vips[i] = netip.MustParseAddr("2001:db8:1::" + string(rune('1'+i)))
	}
	return DesiredRule{Key: key, VPCRef: vpcRef, VIPAddresses: vips}
}

func TestNodeQuotaEnforcer_AllowsWithinLimits(t *testing.T) {
	e := NewNodeQuotaEnforcer(10, 100)
	ok, err := e.CheckAndReserve(context.Background(), testRuleWithVIPs(testRuleKeyR1, "vpc-1", 1))
	if err != nil {
		t.Fatalf("CheckAndReserve: unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("CheckAndReserve: want true, well within limits")
	}
}

func TestNodeQuotaEnforcer_DeniesOverTenantLimit(t *testing.T) {
	e := NewNodeQuotaEnforcer(2, 100)
	for i, name := range []string{testRuleKeyR1, testRuleKeyR2} {
		ok, err := e.CheckAndReserve(context.Background(), testRuleWithVIPs(name, "vpc-1", 1))
		if err != nil || !ok {
			t.Fatalf("CheckAndReserve rule %d: ok=%v err=%v, want true", i, ok, err)
		}
	}

	ok, err := e.CheckAndReserve(context.Background(), testRuleWithVIPs("ns/r3", "vpc-1", 1))
	if err != nil {
		t.Fatalf("CheckAndReserve: unexpected error: %v", err)
	}
	if ok {
		t.Fatal("CheckAndReserve: want false, third rule exceeds per-tenant limit of 2")
	}
}

func TestNodeQuotaEnforcer_DifferentTenantsDoNotShareLimit(t *testing.T) {
	e := NewNodeQuotaEnforcer(1, 100)
	if ok, err := e.CheckAndReserve(context.Background(), testRuleWithVIPs("ns/a", "vpc-1", 1)); err != nil || !ok {
		t.Fatalf("vpc-1 rule: ok=%v err=%v, want true", ok, err)
	}
	if ok, err := e.CheckAndReserve(context.Background(), testRuleWithVIPs("ns/b", "vpc-2", 1)); err != nil || !ok {
		t.Fatalf("vpc-2 rule: ok=%v err=%v, want true (different tenant, own limit)", ok, err)
	}
}

func TestNodeQuotaEnforcer_DeniesOverNodeWideEntryLimit(t *testing.T) {
	e := NewNodeQuotaEnforcer(100, 3)
	// A dual-stack rule with 3 VIPs fills the node-wide 3-entry budget
	// exactly.
	if ok, err := e.CheckAndReserve(context.Background(), testRuleWithVIPs(testRuleKeyR1, "vpc-1", 3)); err != nil || !ok {
		t.Fatalf("first rule: ok=%v err=%v, want true", ok, err)
	}

	ok, err := e.CheckAndReserve(context.Background(), testRuleWithVIPs(testRuleKeyR2, "vpc-2", 1))
	if err != nil {
		t.Fatalf("CheckAndReserve: unexpected error: %v", err)
	}
	if ok {
		t.Fatal("CheckAndReserve: want false, node-wide rule_table capacity is exhausted")
	}
}

func TestNodeQuotaEnforcer_ReapplyIsIdempotent(t *testing.T) {
	e := NewNodeQuotaEnforcer(1, 100)
	rule := testRuleWithVIPs(testRuleKeyR1, "vpc-1", 1)

	if ok, err := e.CheckAndReserve(context.Background(), rule); err != nil || !ok {
		t.Fatalf("first CheckAndReserve: ok=%v err=%v, want true", ok, err)
	}
	// Re-checking the SAME rule.Key on a later reconcile pass must not
	// double-count it against its own tenant's limit of 1 (see
	// Engine.Reconcile's "apply everything in desired" convention).
	if ok, err := e.CheckAndReserve(context.Background(), rule); err != nil || !ok {
		t.Fatalf("second CheckAndReserve (re-apply): ok=%v err=%v, want true (idempotent)", ok, err)
	}

	total, tenants := e.Stats()
	if total != 1 {
		t.Errorf("totalEntries = %d, want 1 (re-apply must not double-reserve)", total)
	}
	if tenants["vpc-1"] != 1 {
		t.Errorf("tenantRuleCounts[vpc-1] = %d, want 1", tenants["vpc-1"])
	}
}

func TestNodeQuotaEnforcer_ReleaseFreesReservation(t *testing.T) {
	e := NewNodeQuotaEnforcer(1, 100)
	rule := testRuleWithVIPs(testRuleKeyR1, "vpc-1", 2)

	if ok, err := e.CheckAndReserve(context.Background(), rule); err != nil || !ok {
		t.Fatalf("CheckAndReserve: ok=%v err=%v, want true", ok, err)
	}
	if err := e.Release(context.Background(), rule.Key); err != nil {
		t.Fatalf("Release: unexpected error: %v", err)
	}

	total, tenants := e.Stats()
	if total != 0 {
		t.Errorf("totalEntries after Release = %d, want 0", total)
	}
	if _, ok := tenants["vpc-1"]; ok {
		t.Errorf("tenantRuleCounts still contains vpc-1 after Release: %+v", tenants)
	}

	// Capacity freed by Release must be usable by a new rule.
	if ok, err := e.CheckAndReserve(context.Background(), testRuleWithVIPs(testRuleKeyR2, "vpc-1", 1)); err != nil || !ok {
		t.Fatalf("CheckAndReserve after Release: ok=%v err=%v, want true (capacity freed)", ok, err)
	}
}

func TestNodeQuotaEnforcer_ReleaseUnknownKeyIsNoop(t *testing.T) {
	e := NewNodeQuotaEnforcer(10, 100)
	if err := e.Release(context.Background(), "never-reserved"); err != nil {
		t.Fatalf("Release of unreserved key: unexpected error: %v", err)
	}
}

func TestNodeQuotaEnforcer_ReapplyWithChangedVIPCountAdjustsTotal(t *testing.T) {
	e := NewNodeQuotaEnforcer(10, 100)
	rule := testRuleWithVIPs(testRuleKeyR1, "vpc-1", 1)
	if ok, err := e.CheckAndReserve(context.Background(), rule); err != nil || !ok {
		t.Fatalf("first CheckAndReserve: ok=%v err=%v, want true", ok, err)
	}

	// Same rule.Key, now dual-stack (2 VIPs instead of 1).
	rule2 := testRuleWithVIPs(testRuleKeyR1, "vpc-1", 2)
	if ok, err := e.CheckAndReserve(context.Background(), rule2); err != nil || !ok {
		t.Fatalf("second CheckAndReserve: ok=%v err=%v, want true", ok, err)
	}

	total, _ := e.Stats()
	if total != 2 {
		t.Errorf("totalEntries after VIP count change = %d, want 2 (not 3 -- must replace, not add)", total)
	}
}
