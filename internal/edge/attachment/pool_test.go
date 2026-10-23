// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"errors"
	"net/netip"
	"testing"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func TestNextFree(t *testing.T) {
	pool := netip.MustParsePrefix("fd00::/126")
	var held []galacticv1alpha1.EdgeAllocation
	got := make([]string, 0, 3)
	for range 3 {
		addr, err := nextFree(pool, held)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, addr.String())
		held = withAllocation(held, addr.String(), "ns/a", addr.String())
	}
	if want := []string{"fd00::1", "fd00::2", "fd00::3"}; len(got) != 3 || got[0] != want[0] || got[2] != want[2] {
		t.Fatalf("allocated %v, want %v: the pool's first address is never handed out", got, want)
	}
	if _, err := nextFree(pool, held); !errors.Is(err, errPoolExhausted) {
		t.Fatalf("full pool = %v", err)
	}
	held = withoutAllocation(held, "fd00::2")
	if addr, err := nextFree(pool, held); err != nil || addr.String() != "fd00::2" {
		t.Fatalf("after freeing fd00::2: %v, %v", addr, err)
	}
	if a, ok := allocationFor(held, "fd00::3"); !ok || a != "fd00::3" {
		t.Errorf("allocationFor = %q, %t", a, ok)
	}
}

func TestPoolChecks(t *testing.T) {
	for _, raw := range []string{"fd00::/63", "fd00::/121", "fd00::1/120", "10.0.0.0/24", "bogus"} {
		if _, err := parsePool(raw); err == nil {
			t.Errorf("parsePool accepted %q", raw)
		}
	}
	vpc := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00:10::/48")}
	if !insideAny(netip.MustParsePrefix("fd00:10:0:e::/120"), vpc) {
		t.Error("pool inside the VPC refused")
	}
	if insideAny(netip.MustParsePrefix("fd00:11::/120"), vpc) || insideAny(netip.MustParsePrefix("fd00::/32"), vpc) {
		t.Error("pool outside the VPC accepted")
	}
	a, b := netip.MustParsePrefix("fd00::/64"), netip.MustParsePrefix("fd00::100/120")
	if !overlaps(a, b) || !overlaps(b, a) || overlaps(b, netip.MustParsePrefix("fd00::200/120")) {
		t.Error("overlap check wrong")
	}
}
