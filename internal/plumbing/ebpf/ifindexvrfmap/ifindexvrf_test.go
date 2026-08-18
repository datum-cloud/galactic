// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"errors"
	"testing"
)

const testBlock uint64 = 0x2001_0DB8_FF01

var errIntentionalTestFailure = errors.New("ifindexvrfmap: intentional test failure")

func newTestIfindexVRFTable(clock func() uint64) (*IfindexVRFTable, *fakeTable) {
	ft := newFakeTable()
	return &IfindexVRFTable{table: ft, clock: clock, generation: make(map[uint32]uint64)}, ft
}

func constClock(value uint64) func() uint64 {
	return func() uint64 { return value }
}

func TestIfindexVRFTable_RegisterAndGet(t *testing.T) {
	it, _ := newTestIfindexVRFTable(constClock(7))

	if err := it.Register(42, testBlock, 0x123); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	entry, ok, err := it.Get(42)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after Register")
	}
	want := IfindexVRFEntry{Ifindex: 42, Block: testBlock, Argument: 0x123, Generation: 7}
	if entry != want {
		t.Errorf("Get = %+v, want %+v", entry, want)
	}
}

func TestIfindexVRFTable_GetMissingEntry(t *testing.T) {
	it, _ := newTestIfindexVRFTable(constClock(1))

	_, ok, err := it.Get(42)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if ok {
		t.Errorf("Get: ok = true for an entry never registered")
	}
}

func TestIfindexVRFTable_RegisterRejectsReservedArgumentZero(t *testing.T) {
	it, ft := newTestIfindexVRFTable(constClock(1))

	if err := it.Register(42, testBlock, 0x000); err == nil {
		t.Errorf("Register(argument=0x000) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("Register(argument=0x000) wrote %d entries, want 0", ft.len())
	}
}

func TestIfindexVRFTable_RegisterRejectsBlockOverflow(t *testing.T) {
	it, ft := newTestIfindexVRFTable(constClock(1))

	const overflowBlock = uint64(1) << 48
	if err := it.Register(42, overflowBlock, 0x123); err == nil {
		t.Errorf("Register(overflowing block) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("Register(overflowing block) wrote an entry, want none")
	}
}

func TestIfindexVRFTable_RegisterOverwrites(t *testing.T) {
	it, _ := newTestIfindexVRFTable(constClock(1))

	if err := it.Register(42, testBlock, 0x123); err != nil {
		t.Fatalf("first Register: unexpected error: %v", err)
	}
	it.clock = constClock(99)
	if err := it.Register(42, testBlock, 0x456); err != nil {
		t.Fatalf("second Register: unexpected error: %v", err)
	}

	entry, ok, err := it.Get(42)
	if err != nil || !ok {
		t.Fatalf("Get after re-register: ok=%v err=%v", ok, err)
	}
	if entry.Argument != 0x456 {
		t.Errorf("Argument = %#x after re-register, want %#x", entry.Argument, 0x456)
	}
	if entry.Generation != 99 {
		t.Errorf("Generation = %d after re-register, want 99", entry.Generation)
	}
}

func TestIfindexVRFTable_Unregister(t *testing.T) {
	it, ft := newTestIfindexVRFTable(constClock(1))

	if err := it.Register(42, testBlock, 0x123); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}
	if err := it.Unregister(42); err != nil {
		t.Fatalf("Unregister: unexpected error: %v", err)
	}
	if ft.len() != 0 {
		t.Errorf("table has %d entries after Unregister, want 0", ft.len())
	}
	if _, ok, err := it.Get(42); err != nil || ok {
		t.Errorf("Get after Unregister: ok=%v err=%v, want ok=false", ok, err)
	}
}

func TestIfindexVRFTable_UnregisterAbsentIsNotError(t *testing.T) {
	it, _ := newTestIfindexVRFTable(constClock(1))

	if err := it.Unregister(42); err != nil {
		t.Errorf("Unregister(never-registered entry) = %v, want nil", err)
	}
}

func TestIfindexVRFTable_List(t *testing.T) {
	it, _ := newTestIfindexVRFTable(constClock(1))

	if err := it.Register(42, testBlock, 0x001); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := it.Register(43, testBlock, 0x002); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entries, err := it.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2: %+v", len(entries), entries)
	}
}

func TestIfindexVRFTable_Generation(t *testing.T) {
	it, _ := newTestIfindexVRFTable(constClock(123))
	if got := it.Generation(); got != 123 {
		t.Errorf("Generation() = %d, want 123", got)
	}
}

func TestIfindexVRFTable_Reconcile_RemovesStaleKeepsLive(t *testing.T) {
	it, _ := newTestIfindexVRFTable(constClock(10))

	if err := it.Register(42, testBlock, 0x100); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := it.Register(43, testBlock, 0x200); err != nil {
		t.Fatalf("Register: %v", err)
	}

	live := map[uint32]struct{}{43: {}}
	removed, err := it.Reconcile(live, 20)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Ifindex != 42 {
		t.Fatalf("Reconcile removed = %+v, want exactly ifindex 42", removed)
	}
	if _, ok, err := it.Get(42); err != nil || ok {
		t.Errorf("Get(42) after Reconcile: ok=%v err=%v, want gone", ok, err)
	}
	if _, ok, err := it.Get(43); err != nil || !ok {
		t.Errorf("Get(43) after Reconcile: ok=%v err=%v, want it to survive", ok, err)
	}
}

func TestIfindexVRFTable_Reconcile_RegistrationMidSweepSurvives(t *testing.T) {
	it, _ := newTestIfindexVRFTable(constClock(10))

	if err := it.Register(42, testBlock, 0x100); err != nil {
		t.Fatalf("Register(stale): unexpected error: %v", err)
	}

	const cutoff = 20
	it.clock = constClock(30)
	if err := it.Register(43, testBlock, 0x200); err != nil {
		t.Fatalf("Register(mid-sweep): unexpected error: %v", err)
	}

	removed, err := it.Reconcile(map[uint32]struct{}{}, cutoff)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Ifindex != 42 {
		t.Fatalf("Reconcile removed = %+v, want exactly ifindex 42", removed)
	}
	if _, ok, err := it.Get(43); err != nil || !ok {
		t.Fatalf("Get(43) after Reconcile: ok=%v err=%v, want the mid-sweep registration to have survived", ok, err)
	}
}

func TestIfindexVRFTable_Reconcile_ContinuesPastDeleteFailure(t *testing.T) {
	it, ft := newTestIfindexVRFTable(constClock(10))

	if err := it.Register(42, testBlock, 0x100); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := it.Register(43, testBlock, 0x200); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sabotaged := &deleteFailingTable{fakeTable: ft, failKey: 42}
	sabotagedIT := &IfindexVRFTable{table: sabotaged, clock: it.clock, generation: it.generation}

	removed, err := sabotagedIT.Reconcile(map[uint32]struct{}{}, 20)
	if err == nil {
		t.Fatalf("Reconcile: want a non-nil error when a delete fails")
	}
	if !errors.Is(err, errIntentionalTestFailure) {
		t.Errorf("Reconcile error = %v, want it to wrap errIntentionalTestFailure", err)
	}
	if len(removed) != 1 || removed[0].Ifindex != 43 {
		t.Fatalf("Reconcile removed = %+v, want exactly ifindex 43", removed)
	}
}

type deleteFailingTable struct {
	*fakeTable
	failKey uint32
}

func (d *deleteFailingTable) Delete(key any) error {
	if k, ok := key.(uint32); ok && k == d.failKey {
		return errIntentionalTestFailure
	}
	return d.fakeTable.Delete(key)
}
