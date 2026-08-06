// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

func newTestFunctionTable() (*FunctionTable, *fakeTable) {
	ft := newFakeTable()
	return &FunctionTable{table: ft}, ft
}

func TestFunctionTable_RegisterAndGet(t *testing.T) {
	ft2, _ := newTestFunctionTable()

	if err := ft2.Register(testBlock, uformat.FunctionEndDT46); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	entry, ok, err := ft2.Get(testBlock, uformat.FunctionEndDT46)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after Register")
	}
	want := FunctionEntry{Block: testBlock, Function: uformat.FunctionEndDT46, Behavior: BehaviorEndDT46}
	if entry != want {
		t.Errorf("Get = %+v, want %+v", entry, want)
	}
}

// TestFunctionTable_RegisterFutureDT2Behavior covers design plan R3: the
// reserved-for-future uEnd.DT2 (0xF) Function value must register cleanly
// today, even though nothing consumes BEHAVIOR_END_DT2 yet.
func TestFunctionTable_RegisterFutureDT2Behavior(t *testing.T) {
	ft2, _ := newTestFunctionTable()

	if err := ft2.Register(testBlock, uformat.FunctionEndDT2); err != nil {
		t.Fatalf("Register(FunctionEndDT2): unexpected error: %v", err)
	}
	entry, ok, err := ft2.Get(testBlock, uformat.FunctionEndDT2)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if entry.Behavior != BehaviorEndDT2 {
		t.Errorf("Behavior = %d, want BehaviorEndDT2 (%d)", entry.Behavior, BehaviorEndDT2)
	}
}

func TestFunctionTable_RegisterRejectsUndefinedFunction(t *testing.T) {
	ft2, ft := newTestFunctionTable()

	if err := ft2.Register(testBlock, 0x3); err == nil {
		t.Errorf("Register(function=0x3) = nil error, want rejection (only 0xE/0xF are defined, design plan R3)")
	}
	if ft.len() != 0 {
		t.Errorf("Register(undefined function) wrote an entry, want none")
	}
}

func TestFunctionTable_Unregister(t *testing.T) {
	ft2, ft := newTestFunctionTable()

	if err := ft2.Register(testBlock, uformat.FunctionEndDT46); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ft2.Unregister(testBlock, uformat.FunctionEndDT46); err != nil {
		t.Fatalf("Unregister: unexpected error: %v", err)
	}
	if ft.len() != 0 {
		t.Errorf("table has %d entries after Unregister, want 0", ft.len())
	}
}

func TestFunctionTable_UnregisterAbsentIsNotError(t *testing.T) {
	ft2, _ := newTestFunctionTable()

	if err := ft2.Unregister(testBlock, uformat.FunctionEndDT46); err != nil {
		t.Errorf("Unregister(never-registered entry) = %v, want nil", err)
	}
}

// TestFunctionTable_OneEntryPerBlockAndFunction covers design plan §4.4:
// "one entry per (active Block x defined Function)" -- the same Function
// under a different Block is a distinct entry.
func TestFunctionTable_OneEntryPerBlockAndFunction(t *testing.T) {
	ft2, _ := newTestFunctionTable()

	const blockA, blockB = uint64(0x0102030405AA), uint64(0x0A0B0C0D0E0F)
	if err := ft2.Register(blockA, uformat.FunctionEndDT46); err != nil {
		t.Fatalf("Register(blockA): %v", err)
	}
	if _, ok, err := ft2.Get(blockB, uformat.FunctionEndDT46); err != nil || ok {
		t.Errorf("Get(blockB) before its own Register: ok=%v err=%v, want ok=false", ok, err)
	}

	if err := ft2.Register(blockB, uformat.FunctionEndDT46); err != nil {
		t.Fatalf("Register(blockB): %v", err)
	}
	entries, err := ft2.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2: %+v", len(entries), entries)
	}
}

func TestFunctionTable_List(t *testing.T) {
	ft2, _ := newTestFunctionTable()

	if err := ft2.Register(testBlock, uformat.FunctionEndDT46); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entries, err := ft2.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List returned %d entries, want 1: %+v", len(entries), entries)
	}
	want := FunctionEntry{Block: testBlock, Function: uformat.FunctionEndDT46, Behavior: BehaviorEndDT46}
	if entries[0] != want {
		t.Errorf("List()[0] = %+v, want %+v", entries[0], want)
	}
}
