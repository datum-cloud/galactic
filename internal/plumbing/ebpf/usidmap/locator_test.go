// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import "testing"

func newTestLocatorTable(clock func() uint64) (*LocatorTable, *fakeTable) {
	ft := newFakeTable()
	return &LocatorTable{table: ft, clock: clock}, ft
}

func TestLocatorTable_RegisterAndGet(t *testing.T) {
	lt, _ := newTestLocatorTable(constClock(5))

	if err := lt.Register(testBlock, 0x0010); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	entry, ok, err := lt.Get(testBlock, 0x0010)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after Register")
	}
	want := LocatorEntry{Block: testBlock, NodeID: 0x0010, Generation: 5}
	if entry != want {
		t.Errorf("Get = %+v, want %+v", entry, want)
	}
}

func TestLocatorTable_RegisterRejectsNodeIDOutOfRange(t *testing.T) {
	lt, ft := newTestLocatorTable(constClock(1))

	// 0xE000 falls in the Function/Argument universe, not Node-ID's
	// reserved range (design plan §10's "Node-ID range not validated
	// anywhere" risk row, closed here by rejecting it outright).
	if err := lt.Register(testBlock, 0xE000); err == nil {
		t.Errorf("Register(node-id=0xE000) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("Register(out-of-range node-id) wrote an entry, want none")
	}
}

func TestLocatorTable_RegisterBumpsGenerationOnReregister(t *testing.T) {
	lt, _ := newTestLocatorTable(constClock(1))

	if err := lt.Register(testBlock, 0x0010); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	lt.clock = constClock(2)
	if err := lt.Register(testBlock, 0x0010); err != nil {
		t.Fatalf("second Register: %v", err)
	}

	entry, ok, err := lt.Get(testBlock, 0x0010)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if entry.Generation != 2 {
		t.Errorf("Generation after re-register = %d, want 2", entry.Generation)
	}
}

func TestLocatorTable_Unregister(t *testing.T) {
	lt, ft := newTestLocatorTable(constClock(1))

	if err := lt.Register(testBlock, 0x0010); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := lt.Unregister(testBlock, 0x0010); err != nil {
		t.Fatalf("Unregister: unexpected error: %v", err)
	}
	if ft.len() != 0 {
		t.Errorf("table has %d entries after Unregister, want 0", ft.len())
	}
}

func TestLocatorTable_UnregisterAbsentIsNotError(t *testing.T) {
	lt, _ := newTestLocatorTable(constClock(1))

	if err := lt.Unregister(testBlock, 0x0010); err != nil {
		t.Errorf("Unregister(never-registered entry) = %v, want nil", err)
	}
}

// TestLocatorTable_MultipleConcurrentBlocks covers design plan R7: more
// than one concurrently active uSID Block on the same node, without
// requiring a code change -- registering a second Block must not disturb
// the first's entry.
func TestLocatorTable_MultipleConcurrentBlocks(t *testing.T) {
	lt, _ := newTestLocatorTable(constClock(1))

	const blockA, blockB = uint64(0x0102030405AA), uint64(0x0A0B0C0D0E0F)
	if err := lt.Register(blockA, 0x0010); err != nil {
		t.Fatalf("Register(blockA): %v", err)
	}
	if err := lt.Register(blockB, 0x0020); err != nil {
		t.Fatalf("Register(blockB): %v", err)
	}

	entries, err := lt.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2: %+v", len(entries), entries)
	}
}

func TestLocatorTable_List(t *testing.T) {
	lt, _ := newTestLocatorTable(constClock(9))

	if err := lt.Register(testBlock, 0x0010); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entries, err := lt.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List returned %d entries, want 1: %+v", len(entries), entries)
	}
	want := LocatorEntry{Block: testBlock, NodeID: 0x0010, Generation: 9}
	if entries[0] != want {
		t.Errorf("List()[0] = %+v, want %+v", entries[0], want)
	}
}
