// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nptv6map

import (
	"errors"
	"net"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/nptv6"
)

// testBlock is an arbitrary 48-bit Block value, mirroring usidmap's own
// testBlock constant.
const testBlock uint64 = 0x2001_0DB8_FF01

// errIntentionalTestFailure is a sentinel error used to simulate one
// specific underlying-table call failing.
var errIntentionalTestFailure = errors.New("nptv6map: intentional test failure")

func newTestNPTv6Table(clock func() uint64) (*NPTv6Table, *fakeTable) {
	ft := newFakeTable()
	return &NPTv6Table{table: ft, clock: clock, generation: make(map[NPTv6Key]uint64)}, ft
}

func constClock(value uint64) func() uint64 {
	return func() uint64 { return value }
}

// testMapping returns a valid, small /48 RFC 6296 mapping usable across
// this file's tests (nptv6.Mapping only supports prefixes /48 or shorter --
// see internal/plumbing/nptv6/doc.go).
func testMapping(t *testing.T) nptv6.Mapping {
	t.Helper()
	_, ula, err := net.ParseCIDR("fd00:1::/48")
	if err != nil {
		t.Fatalf("parse ULAPrefix: %v", err)
	}
	_, pub, err := net.ParseCIDR("2001:db8:1::/48")
	if err != nil {
		t.Fatalf("parse PublicPrefix: %v", err)
	}
	return nptv6.Mapping{ULAPrefix: ula, PublicPrefix: pub}
}

func TestNPTv6Table_RegisterAndGet(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(7))
	mapping := testMapping(t)

	if err := nt.Register(testBlock, 0x123, mapping); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	entry, ok, err := nt.Get(testBlock, 0x123)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after Register")
	}
	if entry.Generation != 7 {
		t.Errorf("Generation = %d, want 7", entry.Generation)
	}
	wantAdjustment, err := mapping.Adjustment()
	if err != nil {
		t.Fatalf("compute want adjustment: %v", err)
	}
	if entry.Adjustment != wantAdjustment {
		t.Errorf("Adjustment = %#x, want %#x", entry.Adjustment, wantAdjustment)
	}
	if !entry.Mapping.ULAPrefix.IP.Equal(mapping.ULAPrefix.IP) {
		t.Errorf("ULAPrefix = %v, want %v", entry.Mapping.ULAPrefix, mapping.ULAPrefix)
	}
	if !entry.Mapping.PublicPrefix.IP.Equal(mapping.PublicPrefix.IP) {
		t.Errorf("PublicPrefix = %v, want %v", entry.Mapping.PublicPrefix, mapping.PublicPrefix)
	}
	if ones, _ := entry.Mapping.ULAPrefix.Mask.Size(); ones != 48 {
		t.Errorf("ULAPrefix mask = /%d, want /48", ones)
	}
}

func TestNPTv6Table_GetMissingEntry(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(1))

	_, ok, err := nt.Get(testBlock, 0x123)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if ok {
		t.Errorf("Get: ok = true for an entry never registered")
	}
}

func TestNPTv6Table_RegisterRejectsReservedArgumentZero(t *testing.T) {
	nt, ft := newTestNPTv6Table(constClock(1))

	if err := nt.Register(testBlock, 0x000, testMapping(t)); err == nil {
		t.Errorf("Register(argument=0x000) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("Register(argument=0x000) wrote %d entries, want 0", ft.len())
	}
}

func TestNPTv6Table_RegisterRejectsBlockOverflow(t *testing.T) {
	nt, ft := newTestNPTv6Table(constClock(1))

	const overflowBlock = uint64(1) << 48
	if err := nt.Register(overflowBlock, 0x123, testMapping(t)); err == nil {
		t.Errorf("Register(overflowing block) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("Register(overflowing block) wrote an entry, want none")
	}
}

func TestNPTv6Table_RegisterRejectsInvalidMapping(t *testing.T) {
	nt, ft := newTestNPTv6Table(constClock(1))

	if err := nt.Register(testBlock, 0x123, nptv6.Mapping{}); err == nil {
		t.Errorf("Register(zero-value mapping) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("Register(invalid mapping) wrote an entry, want none")
	}
}

// TestNPTv6Table_RegisterOverwritesNoCounterState confirms re-registering an
// existing key is a plain overwrite (no read-modify-write step) -- unlike
// usidmap.VRFTable.Register, nptv6_table has no counters to preserve.
func TestNPTv6Table_RegisterOverwritesNoCounterState(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(1))

	if err := nt.Register(testBlock, 0x123, testMapping(t)); err != nil {
		t.Fatalf("first Register: unexpected error: %v", err)
	}

	nt.clock = constClock(99)
	_, ula, _ := net.ParseCIDR("fd00:2::/48")
	_, pub, _ := net.ParseCIDR("2001:db8:2::/48")
	second := nptv6.Mapping{ULAPrefix: ula, PublicPrefix: pub}
	if err := nt.Register(testBlock, 0x123, second); err != nil {
		t.Fatalf("second Register: unexpected error: %v", err)
	}

	entry, ok, err := nt.Get(testBlock, 0x123)
	if err != nil || !ok {
		t.Fatalf("Get after re-register: ok=%v err=%v", ok, err)
	}
	if entry.Generation != 99 {
		t.Errorf("Generation = %d after re-register, want 99", entry.Generation)
	}
	if !entry.Mapping.ULAPrefix.IP.Equal(second.ULAPrefix.IP) {
		t.Errorf("ULAPrefix after re-register = %v, want the second mapping's %v",
			entry.Mapping.ULAPrefix, second.ULAPrefix)
	}
}

func TestNPTv6Table_RegisterPropagatesPutFailure(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(1))
	sabotaged := &putFailingTable{fakeTable: newFakeTable()}
	sabotagedNT := &NPTv6Table{table: sabotaged, clock: nt.clock, generation: make(map[NPTv6Key]uint64)}

	if err := sabotagedNT.Register(testBlock, 0x123, testMapping(t)); err == nil {
		t.Fatalf("Register: want a non-nil error when the underlying Put fails")
	} else if !errors.Is(err, errIntentionalTestFailure) {
		t.Errorf("Register error = %v, want it to wrap errIntentionalTestFailure", err)
	}
}

type putFailingTable struct {
	*fakeTable
}

func (p *putFailingTable) Put(key, value any) error {
	return errIntentionalTestFailure
}

func TestNPTv6Table_Unregister(t *testing.T) {
	nt, ft := newTestNPTv6Table(constClock(1))

	if err := nt.Register(testBlock, 0x123, testMapping(t)); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}
	if err := nt.Unregister(testBlock, 0x123); err != nil {
		t.Fatalf("Unregister: unexpected error: %v", err)
	}
	if ft.len() != 0 {
		t.Errorf("table has %d entries after Unregister, want 0", ft.len())
	}
	if _, ok, err := nt.Get(testBlock, 0x123); err != nil || ok {
		t.Errorf("Get after Unregister: ok=%v err=%v, want ok=false", ok, err)
	}
}

func TestNPTv6Table_UnregisterAbsentIsNotError(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(1))

	if err := nt.Unregister(testBlock, 0x123); err != nil {
		t.Errorf("Unregister(never-registered entry) = %v, want nil", err)
	}
}

func TestNPTv6Table_List(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(1))
	mapping := testMapping(t)

	if err := nt.Register(testBlock, 0x001, mapping); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := nt.Register(testBlock, 0x002, mapping); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entries, err := nt.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2: %+v", len(entries), entries)
	}
}

func TestNPTv6Table_Generation(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(123))
	if got := nt.Generation(); got != 123 {
		t.Errorf("Generation() = %d, want 123", got)
	}
}

func TestNPTv6Table_Reconcile_RemovesStaleEntry(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(10))

	if err := nt.Register(testBlock, 0x100, testMapping(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	removed, err := nt.Reconcile(map[NPTv6Key]struct{}{}, 20)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Argument != 0x100 {
		t.Fatalf("Reconcile removed = %+v, want exactly one entry for argument 0x100", removed)
	}
	if _, ok, err := nt.Get(testBlock, 0x100); err != nil || ok {
		t.Errorf("Get after Reconcile: ok=%v err=%v, want the stale entry gone", ok, err)
	}
}

func TestNPTv6Table_Reconcile_KeepsLiveEntry(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(10))

	if err := nt.Register(testBlock, 0x100, testMapping(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	live := map[NPTv6Key]struct{}{{Block: testBlock, Argument: 0x100}: {}}
	removed, err := nt.Reconcile(live, 20)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("Reconcile removed = %+v, want none (entry is live)", removed)
	}
	if _, ok, err := nt.Get(testBlock, 0x100); err != nil || !ok {
		t.Errorf("Get after Reconcile: ok=%v err=%v, want the live entry to remain", ok, err)
	}
}

// TestNPTv6Table_Reconcile_RegistrationMidSweepSurvives mirrors
// usidmap.VRFTable's own race-scenario test, adapted to this table's
// in-memory Generation bookkeeping (see doc.go): a Register call landing
// after cutoff was captured must survive a Reconcile call whose live set
// predates it.
func TestNPTv6Table_Reconcile_RegistrationMidSweepSurvives(t *testing.T) {
	nt, _ := newTestNPTv6Table(constClock(10))

	if err := nt.Register(testBlock, 0x100, testMapping(t)); err != nil {
		t.Fatalf("Register(stale): unexpected error: %v", err)
	}

	const cutoff = 20

	nt.clock = constClock(30)
	if err := nt.Register(testBlock, 0x200, testMapping(t)); err != nil {
		t.Fatalf("Register(mid-sweep): unexpected error: %v", err)
	}

	live := map[NPTv6Key]struct{}{}
	removed, err := nt.Reconcile(live, cutoff)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Argument != 0x100 {
		t.Fatalf("Reconcile removed = %+v, want exactly the stale 0x100 entry", removed)
	}
	if _, ok, err := nt.Get(testBlock, 0x200); err != nil || !ok {
		t.Fatalf("Get(0x200) after Reconcile: ok=%v err=%v, want the mid-sweep registration to have survived", ok, err)
	}
}

func TestNPTv6Table_Reconcile_ContinuesPastDeleteFailure(t *testing.T) {
	nt, ft := newTestNPTv6Table(constClock(10))

	if err := nt.Register(testBlock, 0x100, testMapping(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := nt.Register(testBlock, 0x200, testMapping(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	badKey, err := uformat.NewVRFKey(testBlock, 0x100)
	if err != nil {
		t.Fatalf("NewVRFKey: %v", err)
	}
	sabotaged := &deleteFailingTable{fakeTable: ft, failKey: uint64(badKey)}
	sabotagedNT := &NPTv6Table{table: sabotaged, clock: nt.clock, generation: nt.generation}

	removed, err := sabotagedNT.Reconcile(map[NPTv6Key]struct{}{}, 20)
	if err == nil {
		t.Fatalf("Reconcile: want a non-nil error when a delete fails")
	}
	if !errors.Is(err, errIntentionalTestFailure) {
		t.Errorf("Reconcile error = %v, want it to wrap errIntentionalTestFailure", err)
	}
	if len(removed) != 1 || removed[0].Argument != 0x200 {
		t.Fatalf("Reconcile removed = %+v, want exactly argument 0x200", removed)
	}
}

type deleteFailingTable struct {
	*fakeTable
	failKey uint64
}

func (d *deleteFailingTable) Delete(key any) error {
	if k, ok := key.(uint64); ok && k == d.failKey {
		return errIntentionalTestFailure
	}
	return d.fakeTable.Delete(key)
}
