// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"errors"
	"testing"
)

func newTestVPCAttributionTable(clock func() uint64) (*VPCAttributionTable, *fakeTable) {
	ft := newFakeTable()
	return &VPCAttributionTable{table: ft, clock: clock}, ft
}

func TestVPCAttributionTable_RegisterAndGet(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(7))

	if err := vt.Register(testBlock, 0x123, 0xC0FFEE, 0x42); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	entry, ok, err := vt.Get(testBlock, 0x123)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after Register")
	}
	want := VPCAttributionEntry{
		VRFKey:        VRFKey{Block: testBlock, Argument: 0x123},
		VPC:           0xC0FFEE,
		VPCAttachment: 0x42,
		Generation:    7,
	}
	if entry != want {
		t.Errorf("Get = %+v, want %+v", entry, want)
	}
}

func TestVPCAttributionTable_GetMissingEntry(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(1))

	_, ok, err := vt.Get(testBlock, 0x123)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if ok {
		t.Errorf("Get: ok = true for an entry never registered")
	}
}

func TestVPCAttributionTable_RegisterRejectsReservedArgumentZero(t *testing.T) {
	vt, ft := newTestVPCAttributionTable(constClock(1))

	if err := vt.Register(testBlock, 0x000, 0xC0FFEE, 0x42); err == nil {
		t.Errorf("Register(argument=0x000) = nil error, want rejection, matching VRFTable's own reserved-Argument rule")
	}
	if ft.len() != 0 {
		t.Errorf("Register(argument=0x000) wrote %d entries, want 0 (reject outright, never partially write)", ft.len())
	}
}

// TestVPCAttributionTable_RegisterOverwritesOnReRegister confirms
// re-registering an existing key overwrites its VPC/VPCAttachment and
// Generation outright. Unlike VRFTable, there are no datapath-owned counters
// to carry forward here -- this table's only writer is registerEBPFDatapath
// itself, so a re-registration always reflects the caller's current,
// authoritative identity.
func TestVPCAttributionTable_RegisterOverwritesOnReRegister(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(1))

	if err := vt.Register(testBlock, 0x123, 0x1111, 0x01); err != nil {
		t.Fatalf("first Register: unexpected error: %v", err)
	}

	vt.clock = constClock(99)
	if err := vt.Register(testBlock, 0x123, 0x2222, 0x02); err != nil {
		t.Fatalf("second Register: unexpected error: %v", err)
	}

	entry, ok, err := vt.Get(testBlock, 0x123)
	if err != nil || !ok {
		t.Fatalf("Get after re-register: ok=%v err=%v", ok, err)
	}
	if entry.VPC != 0x2222 || entry.VPCAttachment != 0x02 || entry.Generation != 99 {
		t.Errorf("Get after re-register = %+v, want VPC=0x2222 VPCAttachment=0x02 Generation=99", entry)
	}
}

func TestVPCAttributionTable_Unregister(t *testing.T) {
	vt, ft := newTestVPCAttributionTable(constClock(1))

	if err := vt.Register(testBlock, 0x123, 0xC0FFEE, 0x42); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}
	if err := vt.Unregister(testBlock, 0x123); err != nil {
		t.Fatalf("Unregister: unexpected error: %v", err)
	}
	if ft.len() != 0 {
		t.Errorf("table has %d entries after Unregister, want 0", ft.len())
	}
}

// TestVPCAttributionTable_UnregisterAbsentIsNotError mirrors VRFTable's own
// rule: both the failed-ADD rollback path and the GC sweep call Unregister,
// either of which may race the other having already removed the same entry.
func TestVPCAttributionTable_UnregisterAbsentIsNotError(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(1))

	if err := vt.Unregister(testBlock, 0x123); err != nil {
		t.Errorf("Unregister(never-registered entry) = %v, want nil", err)
	}
}

func TestVPCAttributionTable_List(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(1))

	if err := vt.Register(testBlock, 0x001, 0x1111, 0x01); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := vt.Register(testBlock, 0x002, 0x2222, 0x02); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entries, err := vt.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2: %+v", len(entries), entries)
	}

	byArgument := map[uint16]VPCAttributionEntry{}
	for _, e := range entries {
		byArgument[e.Argument] = e
	}
	if e, ok := byArgument[0x001]; !ok || e.VPC != 0x1111 || e.VPCAttachment != 0x01 || e.Block != testBlock {
		t.Errorf("List entry for argument 0x001 = %+v, ok=%v, want Block=%#x VPC=0x1111 VPCAttachment=0x01",
			e, ok, testBlock)
	}
	if e, ok := byArgument[0x002]; !ok || e.VPC != 0x2222 || e.VPCAttachment != 0x02 || e.Block != testBlock {
		t.Errorf("List entry for argument 0x002 = %+v, ok=%v, want Block=%#x VPC=0x2222 VPCAttachment=0x02",
			e, ok, testBlock)
	}
}

func TestVPCAttributionTable_Generation(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(123))
	if got := vt.Generation(); got != 123 {
		t.Errorf("Generation() = %d, want 123", got)
	}
}

// TestVPCAttributionTable_Reconcile_RemovesStaleEntry and the two tests
// after it mirror VRFTable's own Reconcile coverage: the two tables share
// the exact same generation-cutoff GC algorithm and are meant to be
// reconciled together against the same live set, so their correctness
// arguments are identical -- see VRFTable's Reconcile tests for the fuller
// race-scenario narrative.
func TestVPCAttributionTable_Reconcile_RemovesStaleEntry(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(10))

	if err := vt.Register(testBlock, 0x100, 0x1111, 0x01); err != nil {
		t.Fatalf("Register: %v", err)
	}

	removed, err := vt.Reconcile(map[VRFKey]struct{}{}, 20)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Argument != 0x100 {
		t.Fatalf("Reconcile removed = %+v, want exactly one entry for argument 0x100", removed)
	}
	if _, ok, err := vt.Get(testBlock, 0x100); err != nil || ok {
		t.Errorf("Get after Reconcile: ok=%v err=%v, want the stale entry gone", ok, err)
	}
}

func TestVPCAttributionTable_Reconcile_KeepsLiveEntry(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(10))

	if err := vt.Register(testBlock, 0x100, 0x1111, 0x01); err != nil {
		t.Fatalf("Register: %v", err)
	}

	live := map[VRFKey]struct{}{{Block: testBlock, Argument: 0x100}: {}}
	removed, err := vt.Reconcile(live, 20)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("Reconcile removed = %+v, want none (entry is live)", removed)
	}
}

func TestVPCAttributionTable_Reconcile_RegistrationMidSweepSurvives(t *testing.T) {
	vt, _ := newTestVPCAttributionTable(constClock(10))

	if err := vt.Register(testBlock, 0x100, 0x1111, 0x01); err != nil {
		t.Fatalf("Register(stale): unexpected error: %v", err)
	}

	const cutoff = 20
	vt.clock = constClock(30)
	if err := vt.Register(testBlock, 0x200, 0x2222, 0x02); err != nil {
		t.Fatalf("Register(mid-sweep): unexpected error: %v", err)
	}

	removed, err := vt.Reconcile(map[VRFKey]struct{}{}, cutoff)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Argument != 0x100 {
		t.Fatalf("Reconcile removed = %+v, want exactly the stale 0x100 entry (mid-sweep 0x200 must survive)", removed)
	}
	if _, ok, err := vt.Get(testBlock, 0x200); err != nil || !ok {
		t.Errorf("Get(0x200) after Reconcile: ok=%v err=%v, want the mid-sweep registration to have survived", ok, err)
	}
}

// TestVPCAttributionTable_Reconcile_ContinuesPastDeleteFailure mirrors
// VRFTable's own coverage of the same behavior, reusing deleteFailingTable
// from vrf_test.go.
func TestVPCAttributionTable_Reconcile_ContinuesPastDeleteFailure(t *testing.T) {
	vt, ft := newTestVPCAttributionTable(constClock(10))

	if err := vt.Register(testBlock, 0x100, 0x1111, 0x01); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := vt.Register(testBlock, 0x200, 0x2222, 0x02); err != nil {
		t.Fatalf("Register: %v", err)
	}

	badKey := mustVRFKey(t, testBlock, 0x100)
	sabotaged := &deleteFailingTable{fakeTable: ft, failKey: badKey}
	sabotagedVT := &VPCAttributionTable{table: sabotaged, clock: vt.clock}

	removed, err := sabotagedVT.Reconcile(map[VRFKey]struct{}{}, 20)
	if err == nil {
		t.Fatalf("Reconcile: want a non-nil error when a delete fails")
	}
	if !errors.Is(err, errIntentionalTestFailure) {
		t.Errorf("Reconcile error = %v, want it to wrap errIntentionalTestFailure", err)
	}
	if len(removed) != 1 || removed[0].Argument != 0x200 {
		t.Fatalf("Reconcile removed = %+v, want exactly argument 0x200 (0x100's delete failed but must not block it)",
			removed)
	}
}
