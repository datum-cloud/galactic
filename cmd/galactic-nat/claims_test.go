// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// fakeClaims answers nat_claims lookups from fixed per-CPU counts.
type fakeClaims map[uint32][]uint64

func (f fakeClaims) Lookup(key, valueOut any) error {
	*valueOut.(*[]uint64) = f[key.(uint32)]
	return nil
}

func TestNatCollectorReportsClaims(t *testing.T) {
	c := &natCollector{claims: fakeClaims{
		natprog.ClaimSlot(natprog.TrafficFamilyNAT66, natprog.ClaimProtoTCP, 1):  {4, 6},
		natprog.ClaimSlot(natprog.TrafficFamilyNAT66, natprog.ClaimProtoTCP, 3):  {2},
		natprog.ClaimSlot(natprog.TrafficFamilyNAT64, natprog.ClaimProtoICMP, 8): {1},
	}}
	got := gatherAll(t, c)

	creates := got["galactic_nat_session_creates_total"]
	if len(creates) != 6 {
		t.Errorf("session_creates_total has %d series, want 6 (2 families x 3 protocols): %v", len(creates), creates)
	}
	// Labels sort as family/proto.
	for labels, want := range map[string]float64{"nat66/tcp": 12, "nat64/icmp": 1, "nat66/udp": 0} {
		if creates[labels] != want {
			t.Errorf("session_creates_total{%s} = %v, want %v", labels, creates[labels], want)
		}
	}

	probes := got["galactic_nat_masquerade_claim_probes_total"]
	if len(probes) != int(natprog.ClaimSlots) {
		t.Errorf("claim_probes_total has %d series, want %d", len(probes), natprog.ClaimSlots)
	}
	// Labels sort as family/probes/proto.
	for labels, want := range map[string]float64{
		"nat66/1/tcp": 10, "nat66/3/tcp": 2, "nat64/8/icmp": 1, "nat66/2/tcp": 0,
	} {
		if probes[labels] != want {
			t.Errorf("claim_probes_total{%s} = %v, want %v", labels, probes[labels], want)
		}
	}
}
