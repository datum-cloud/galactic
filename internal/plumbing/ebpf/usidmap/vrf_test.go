// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"errors"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// testBlock is an arbitrary 48-bit Block value used across this package's
// tests that don't specifically target Block's own boundaries -- mirrors
// uformat_test.go's own testBlock constant.
const testBlock uint64 = 0x2001_0DB8_FF01

// errIntentionalTestFailure is a sentinel error deleteFailingTable returns
// to simulate one specific Delete call failing.
var errIntentionalTestFailure = errors.New("usidmap: intentional test failure")

func newTestVRFTable(clock func() uint64) (*VRFTable, *fakeTable) {
	ft := newFakeTable()
	return &VRFTable{table: ft, clock: clock}, ft
}

// mustVRFKey is a small test helper wrapping uformat.NewVRFKey.
func mustVRFKey(t *testing.T, block uint64, argument uint16) uint64 {
	t.Helper()
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		t.Fatalf("NewVRFKey(%#x, %#x): unexpected error: %v", block, argument, err)
	}
	return uint64(key)
}

func TestVRFTable_RegisterAndGet(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(7))

	if err := vt.Register(testBlock, 0x123, 42, EgressKindVeth); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	entry, ok, err := vt.Get(testBlock, 0x123)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Get: entry not found after Register")
	}
	want := VRFEntry{
		VRFKey:     VRFKey{Block: testBlock, Argument: 0x123},
		VRFTableID: 42,
		Generation: 7,
	}
	if entry != want {
		t.Errorf("Get = %+v, want %+v", entry, want)
	}
}

func TestVRFTable_GetMissingEntry(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(1))

	_, ok, err := vt.Get(testBlock, 0x123)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if ok {
		t.Errorf("Get: ok = true for an entry never registered")
	}
}

func TestVRFTable_RegisterRejectsReservedArgumentZero(t *testing.T) {
	vt, ft := newTestVRFTable(constClock(1))

	if err := vt.Register(testBlock, 0x000, 42, EgressKindVeth); err == nil {
		t.Errorf("Register(argument=0x000) = nil error, want rejection (design plan R4/§5.1)")
	}
	if ft.len() != 0 {
		t.Errorf("Register(argument=0x000) wrote %d entries into the table, want 0 (reject outright, never partially write)",
			ft.len())
	}
}

func TestVRFTable_RegisterRejectsBlockOverflow(t *testing.T) {
	vt, ft := newTestVRFTable(constClock(1))

	const overflowBlock = uint64(1) << 48 // one past the 48-bit Block field's max
	if err := vt.Register(overflowBlock, 0x123, 42, EgressKindVeth); err == nil {
		t.Errorf("Register(overflowing block) = nil error, want rejection")
	}
	if ft.len() != 0 {
		t.Errorf("Register(overflowing block) wrote an entry, want none")
	}
}

// TestVRFTable_RegisterOverwritesExistingKeyAndResetsCounters confirms
// that re-registering an existing (block, argument) key overwrites the
// stored VRFTableID/Generation and resets the datapath's own hit counters
// to zero, per Register's documented "always a fresh registration"
// semantics (vrf.go). Packets/Bytes/LastSeenNs are seeded directly into
// the fake table here (bypassing Register, which never sets them) to
// simulate the datapath itself having already recorded traffic against
// this entry before the second Register call.
func TestVRFTable_RegisterOverwritesExistingKeyAndResetsCounters(t *testing.T) {
	vt, ft := newTestVRFTable(constClock(1))

	if err := vt.Register(testBlock, 0x123, 42, EgressKindVeth); err != nil {
		t.Fatalf("first Register: unexpected error: %v", err)
	}

	key := mustVRFKey(t, testBlock, 0x123)
	seeded := prog.UsidVrfValue{VrfTableId: 42, Generation: 1, Packets: 100, Bytes: 5000, LastSeenNs: 123}
	if err := ft.Put(key, seeded); err != nil {
		t.Fatalf("seed simulated traffic: %v", err)
	}

	vt.clock = constClock(99)
	if err := vt.Register(testBlock, 0x123, 43, EgressKindVeth); err != nil {
		t.Fatalf("second Register: unexpected error: %v", err)
	}

	entry, ok, err := vt.Get(testBlock, 0x123)
	if err != nil || !ok {
		t.Fatalf("Get after re-register: ok=%v err=%v", ok, err)
	}
	if entry.VRFTableID != 43 {
		t.Errorf("VRFTableID = %d after re-register, want 43", entry.VRFTableID)
	}
	if entry.Generation != 99 {
		t.Errorf("Generation = %d after re-register, want 99 (the second Register's clock reading)", entry.Generation)
	}
	if entry.Packets != 0 || entry.Bytes != 0 || entry.LastSeenNs != 0 {
		t.Errorf("hit counters after re-register = %+v, want all zero", entry)
	}
}

func TestVRFTable_Unregister(t *testing.T) {
	vt, ft := newTestVRFTable(constClock(1))

	if err := vt.Register(testBlock, 0x123, 42, EgressKindVeth); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}
	if err := vt.Unregister(testBlock, 0x123); err != nil {
		t.Fatalf("Unregister: unexpected error: %v", err)
	}
	if ft.len() != 0 {
		t.Errorf("table has %d entries after Unregister, want 0", ft.len())
	}
	if _, ok, err := vt.Get(testBlock, 0x123); err != nil || ok {
		t.Errorf("Get after Unregister: ok=%v err=%v, want ok=false", ok, err)
	}
}

// TestVRFTable_UnregisterAbsentIsNotError covers design plan §5.1's
// requirement that Unregister is called from both the failed-ADD rollback
// path and the GC sweep, either of which may race the other having
// already removed the same entry -- Unregister must not treat that as an
// error.
func TestVRFTable_UnregisterAbsentIsNotError(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(1))

	if err := vt.Unregister(testBlock, 0x123); err != nil {
		t.Errorf("Unregister(never-registered entry) = %v, want nil", err)
	}
}

// TestVRFTable_VRFKeyIncludesBlock covers design plan R8: two Blocks
// sharing the same Argument must be independently registered, retrieved,
// and unregistered -- registering under one Block must never be visible
// to a Get/Unregister under a different Block.
func TestVRFTable_VRFKeyIncludesBlock(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(1))

	const blockA, blockB = uint64(0x0102030405AA), uint64(0x0A0B0C0D0E0F)
	if err := vt.Register(blockA, 0x123, 1, EgressKindVeth); err != nil {
		t.Fatalf("Register(blockA): unexpected error: %v", err)
	}

	if _, ok, err := vt.Get(blockB, 0x123); err != nil || ok {
		t.Errorf("Get(blockB, same Argument) = ok=%v err=%v, want ok=false (Block must be part of the key)", ok, err)
	}

	if err := vt.Register(blockB, 0x123, 2, EgressKindVeth); err != nil {
		t.Fatalf("Register(blockB): unexpected error: %v", err)
	}
	entryA, ok, err := vt.Get(blockA, 0x123)
	if err != nil || !ok {
		t.Fatalf("Get(blockA) after registering blockB: ok=%v err=%v", ok, err)
	}
	if entryA.VRFTableID != 1 {
		t.Errorf("blockA's entry was clobbered by registering blockB: VRFTableID = %d, want 1", entryA.VRFTableID)
	}
}

func TestVRFTable_List(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(1))

	if err := vt.Register(testBlock, 0x001, 10, EgressKindVeth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := vt.Register(testBlock, 0x002, 20, EgressKindVeth); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entries, err := vt.List()
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2: %+v", len(entries), entries)
	}

	byArgument := map[uint16]VRFEntry{}
	for _, e := range entries {
		byArgument[e.Argument] = e
	}
	if e, ok := byArgument[0x001]; !ok || e.VRFTableID != 10 || e.Block != testBlock {
		t.Errorf("List entry for argument 0x001 = %+v, ok=%v, want Block=%#x VRFTableID=10", e, ok, testBlock)
	}
	if e, ok := byArgument[0x002]; !ok || e.VRFTableID != 20 || e.Block != testBlock {
		t.Errorf("List entry for argument 0x002 = %+v, ok=%v, want Block=%#x VRFTableID=20", e, ok, testBlock)
	}
}

func TestVRFTable_Generation(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(123))
	if got := vt.Generation(); got != 123 {
		t.Errorf("Generation() = %d, want 123", got)
	}
}

// TestVRFTable_Reconcile_RemovesStaleEntry covers the base case: an entry
// registered before the sweep's CRD-list cutoff, whose key is absent from
// the live set, must be removed.
func TestVRFTable_Reconcile_RemovesStaleEntry(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(10))

	if err := vt.Register(testBlock, 0x100, 1, EgressKindVeth); err != nil {
		t.Fatalf("Register: %v", err)
	}

	removed, err := vt.Reconcile(map[VRFKey]struct{}{}, 20 /* cutoff, after generation 10 */)
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

// TestVRFTable_Reconcile_KeepsLiveEntry confirms an entry whose key IS in
// the live set is never removed, regardless of its Generation.
func TestVRFTable_Reconcile_KeepsLiveEntry(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(10))

	if err := vt.Register(testBlock, 0x100, 1, EgressKindVeth); err != nil {
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
	if _, ok, err := vt.Get(testBlock, 0x100); err != nil || !ok {
		t.Errorf("Get after Reconcile: ok=%v err=%v, want the live entry to remain", ok, err)
	}
}

// TestVRFTable_Reconcile_RegistrationMidSweepSurvives is this milestone's
// exit-criterion race scenario (design plan §5.4's closing paragraph;
// implementation plan Milestone 3.3's exit criteria, mirrored again in
// Milestone 7.3's): a Register call landing between the GC sweep's
// list-CRDs step and its delete-stale-entries step must survive, even
// though its Argument cannot possibly appear in a live-CRD snapshot taken
// before the registration happened.
//
// Sequence modeled here, matching the real GC sweep's steps exactly:
//  1. A pre-existing entry (argument 0x100) is registered at generation 10
//     -- its BGPVRFInstance CRD has since been deleted (this entry really
//     is stale).
//  2. The GC controller captures cutoff = VRFTable.Generation() (here,
//  20. *before* listing CRDs.
//  3. Before the GC controller's delete step runs, a brand-new
//     registration (argument 0x200) lands -- e.g. a concurrent CNI ADD on
//     the plugin-binary side -- stamped with generation 30 (after
//     cutoff).
//  4. The GC controller's CRD list (captured at step 2, so it reflects
//     neither the already-deleted 0x100 CRD nor the not-yet-visible 0x200
//     CRD) is empty: live contains neither key.
//  5. Reconcile(live, cutoff) must remove 0x100 (older than cutoff, and
//     genuinely absent from live) but must NOT remove 0x200 (newer than
//     cutoff, even though it is also absent from live) -- reaping it here
//     would deliver a live tenant's traffic nowhere until some later,
//     lucky sweep re-registers it, which is exactly the "delivered into
//     the wrong VRF or dropped" failure design plan §5.1 warns about.
func TestVRFTable_Reconcile_RegistrationMidSweepSurvives(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(10))

	// Step 1: pre-existing, now-genuinely-stale entry.
	if err := vt.Register(testBlock, 0x100, 1, EgressKindVeth); err != nil {
		t.Fatalf("Register(stale): unexpected error: %v", err)
	}

	// Step 2: the GC controller's cutoff, captured before listing CRDs.
	const cutoff = 20

	// Step 3: a Register call lands mid-sweep, after cutoff was captured.
	vt.clock = constClock(30)
	if err := vt.Register(testBlock, 0x200, 2, EgressKindVeth); err != nil {
		t.Fatalf("Register(mid-sweep): unexpected error: %v", err)
	}

	// Step 4: the live-CRD snapshot reflects neither key.
	live := map[VRFKey]struct{}{}

	// Step 5: reconcile.
	removed, err := vt.Reconcile(live, cutoff)
	if err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	if len(removed) != 1 || removed[0].Argument != 0x100 {
		t.Fatalf("Reconcile removed = %+v, want exactly the stale 0x100 entry (mid-sweep 0x200 must survive)", removed)
	}

	if _, ok, err := vt.Get(testBlock, 0x100); err != nil || ok {
		t.Errorf("Get(0x100) after Reconcile: ok=%v err=%v, want the stale entry gone", ok, err)
	}
	entry, ok, err := vt.Get(testBlock, 0x200)
	if err != nil || !ok {
		t.Fatalf("Get(0x200) after Reconcile: ok=%v err=%v, want the mid-sweep registration to have survived", ok, err)
	}
	if entry.VRFTableID != 2 {
		t.Errorf("surviving entry VRFTableID = %d, want 2 (unmodified by Reconcile)", entry.VRFTableID)
	}
}

// TestVRFTable_Reconcile_SurvivorIsCaughtByNextSweep confirms the
// mid-sweep entry that Reconcile deliberately spared is not spared
// forever: once its own generation is safely before a later sweep's
// cutoff, and its Argument is still absent from that later sweep's live
// set (e.g. its CRD really was deleted before its Register call, an
// actually-stale case that merely happened to race the first sweep), the
// next Reconcile call removes it.
func TestVRFTable_Reconcile_SurvivorIsCaughtByNextSweep(t *testing.T) {
	vt, _ := newTestVRFTable(constClock(30))

	if err := vt.Register(testBlock, 0x200, 2, EgressKindVeth); err != nil {
		t.Fatalf("Register: unexpected error: %v", err)
	}

	// First sweep: cutoff (20) predates this entry's generation (30) --
	// spared, per the race-protection behavior under test elsewhere.
	if removed, err := vt.Reconcile(map[VRFKey]struct{}{}, 20); err != nil || len(removed) != 0 {
		t.Fatalf("first Reconcile: removed=%+v err=%v, want none removed", removed, err)
	}

	// Second sweep: cutoff (40) now postdates this entry's generation
	// (30), and it is still absent from live -- must be removed now.
	removed, err := vt.Reconcile(map[VRFKey]struct{}{}, 40)
	if err != nil {
		t.Fatalf("second Reconcile: unexpected error: %v", err)
	}
	if len(removed) != 1 || removed[0].Argument != 0x200 {
		t.Fatalf("second Reconcile removed = %+v, want exactly argument 0x200", removed)
	}
}

// TestVRFTable_Reconcile_ContinuesPastDeleteFailure confirms Reconcile
// attempts every stale candidate even if deleting one of them fails,
// joining the failure into its returned error rather than aborting early.
func TestVRFTable_Reconcile_ContinuesPastDeleteFailure(t *testing.T) {
	vt, ft := newTestVRFTable(constClock(10))

	if err := vt.Register(testBlock, 0x100, 1, EgressKindVeth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := vt.Register(testBlock, 0x200, 2, EgressKindVeth); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Sabotage the underlying table so deleting 0x100's key specifically
	// fails, while 0x200's still succeeds.
	badKey := mustVRFKey(t, testBlock, 0x100)
	sabotaged := &deleteFailingTable{fakeTable: ft, failKey: badKey}
	sabotagedVT := &VRFTable{table: sabotaged, clock: vt.clock}

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

// deleteFailingTable wraps a *fakeTable and fails Delete for one specific
// key, to test Reconcile's continue-past-failure behavior.
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
