// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import "testing"

func claimCount(t *testing.T, objs *NatObjects, slot uint32) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := objs.NatClaims.Lookup(slot, &perCPU); err != nil {
		t.Fatalf("lookup nat_claims[%d]: %v", slot, err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// TestNatClaims_CountsNewSessionsOnce checks that a new session counts one
// claim in its family and protocol's single-probe slot, and that the same
// session's later packets, which reuse its port, count nothing.
func TestNatClaims_CountsNewSessionsOnce(t *testing.T) {
	f := newNAT66Fixture(t)
	udp1 := ClaimSlot(TrafficFamilyNAT66, ClaimProtoUDP, 1)

	f.sendUDP(t)
	if got := claimCount(t, f.objs, udp1); got != 1 {
		t.Fatalf("nat_claims[nat66/udp/1] after a new session = %d, want 1", got)
	}
	f.sendUDP(t)
	f.sendUDP(t)
	if got := claimCount(t, f.objs, udp1); got != 1 {
		t.Errorf("nat_claims[nat66/udp/1] after the same session's later packets = %d, want still 1", got)
	}
	for slot := range ClaimSlots {
		if slot == udp1 {
			continue
		}
		if got := claimCount(t, f.objs, slot); got != 0 {
			t.Errorf("nat_claims[%d] = %d, want 0", slot, got)
		}
	}
}

func TestClaimSlot(t *testing.T) {
	seen := map[uint32]bool{}
	for _, family := range []uint32{TrafficFamilyNAT66, TrafficFamilyNAT64} {
		for _, proto := range []uint32{ClaimProtoTCP, ClaimProtoUDP, ClaimProtoICMP} {
			for probes := 1; probes <= PATProbeLimit; probes++ {
				slot := ClaimSlot(family, proto, probes)
				if slot >= ClaimSlots || seen[slot] {
					t.Fatalf("ClaimSlot(%d, %d, %d) = %d, out of range or reused", family, proto, probes, slot)
				}
				seen[slot] = true
			}
		}
	}
	if uint32(len(seen)) != ClaimSlots {
		t.Errorf("slots used = %d, want all %d", len(seen), ClaimSlots)
	}
}

// TestClaimSlots_MatchesTheMap keeps the Go slot count in step with the
// datapath's nat_claims size, which the C side derives from its own probe
// limit.
func TestClaimSlots_MatchesTheMap(t *testing.T) {
	spec, err := LoadNat()
	if err != nil {
		t.Fatalf("LoadNat: %v", err)
	}
	m := spec.Maps["nat_claims"]
	if m == nil {
		t.Fatal("nat_claims missing from the compiled spec")
	}
	if m.MaxEntries != ClaimSlots {
		t.Errorf("nat_claims has %d entries, natprog.ClaimSlots is %d", m.MaxEntries, ClaimSlots)
	}
}
