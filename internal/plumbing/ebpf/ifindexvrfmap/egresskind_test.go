// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

const (
	tapIfindex  uint32 = 42
	vethIfindex uint32 = 43
)

func assertEgressKind(t *testing.T, table *EgressKindTable, ifindex, want uint32) {
	t.Helper()
	got, ok, err := table.Get(ifindex)
	if err != nil {
		t.Fatalf("Get(%d): unexpected error: %v", ifindex, err)
	}
	if !ok {
		t.Fatalf("Get(%d): no entry, want egress kind %d", ifindex, want)
	}
	if got != want {
		t.Errorf("Get(%d) = %d, want %d", ifindex, got, want)
	}
}

// A VPC holding a tap and a veth attachment on one node must keep both kinds,
// whichever registers last. vrf_table's shared per-VPC value could not.
func TestEgressKindTable_MixedKindsSurviveEitherRegistrationOrder(t *testing.T) {
	type registration struct {
		ifindex uint32
		kind    uint32
	}
	tap := registration{ifindex: tapIfindex, kind: usidmap.EgressKindTap}
	veth := registration{ifindex: vethIfindex, kind: usidmap.EgressKindVeth}

	for _, tt := range []struct {
		name  string
		order []registration
	}{
		{name: "tap then veth", order: []registration{tap, veth}},
		{name: "veth then tap", order: []registration{veth, tap}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			table := NewEgressKindTable(newFakeTable())
			for _, r := range tt.order {
				if err := table.Register(r.ifindex, r.kind); err != nil {
					t.Fatalf("Register(%d, %d): %v", r.ifindex, r.kind, err)
				}
			}
			assertEgressKind(t, table, tapIfindex, usidmap.EgressKindTap)
			assertEgressKind(t, table, vethIfindex, usidmap.EgressKindVeth)
		})
	}
}

func TestEgressKindTable_UnregisterLeavesSiblingIntact(t *testing.T) {
	for _, tt := range []struct {
		name          string
		removed, kept uint32
		keptKind      uint32
	}{
		{name: "remove tap", removed: tapIfindex, kept: vethIfindex, keptKind: usidmap.EgressKindVeth},
		{name: "remove veth", removed: vethIfindex, kept: tapIfindex, keptKind: usidmap.EgressKindTap},
	} {
		t.Run(tt.name, func(t *testing.T) {
			table := NewEgressKindTable(newFakeTable())
			if err := table.Register(tapIfindex, usidmap.EgressKindTap); err != nil {
				t.Fatalf("Register(tap): %v", err)
			}
			if err := table.Register(vethIfindex, usidmap.EgressKindVeth); err != nil {
				t.Fatalf("Register(veth): %v", err)
			}
			if err := table.Unregister(tt.removed); err != nil {
				t.Fatalf("Unregister(%d): %v", tt.removed, err)
			}
			if _, ok, err := table.Get(tt.removed); err != nil || ok {
				t.Errorf("Get(%d) after Unregister: ok=%v err=%v, want no entry", tt.removed, ok, err)
			}
			assertEgressKind(t, table, tt.kept, tt.keptKind)
		})
	}
}

func TestEgressKindTable_UnregisterAbsentIsNotError(t *testing.T) {
	table := NewEgressKindTable(newFakeTable())
	if err := table.Unregister(tapIfindex); err != nil {
		t.Errorf("Unregister(never registered) = %v, want nil", err)
	}
}

func TestEgressKindTable_RegisterOverwrites(t *testing.T) {
	table := NewEgressKindTable(newFakeTable())
	if err := table.Register(tapIfindex, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	// An ifindex freed by a DEL that never ran can be reused by a different
	// kind of attachment, whose own ADD must win.
	if err := table.Register(tapIfindex, usidmap.EgressKindTap); err != nil {
		t.Fatalf("second Register: %v", err)
	}
	assertEgressKind(t, table, tapIfindex, usidmap.EgressKindTap)
}

func TestEgressKindTable_RegisterRejectsUnknownKind(t *testing.T) {
	ft := newFakeTable()
	table := NewEgressKindTable(ft)
	if err := table.Register(tapIfindex, 7); err == nil {
		t.Error("Register(kind=7) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("Register(kind=7) wrote %d entries, want 0", ft.len())
	}
}
