// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"errors"
	"slices"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

const testTrafficCPUs = 2

// fakeCounterTable is an in-memory CounterTable holding each row as its
// per-CPU slice, the shape the kernel map hands back.
type fakeCounterTable struct {
	rows      map[uint64][]prog.UsidVrfTrafficValue
	createErr error
}

func newFakeCounterTable() *fakeCounterTable {
	return &fakeCounterTable{rows: make(map[uint64][]prog.UsidVrfTrafficValue)}
}

func (f *fakeCounterTable) Create(key, value any) error {
	if f.createErr != nil {
		return f.createErr
	}
	k := fakeTableKey(key)
	if _, ok := f.rows[k]; ok {
		return ebpf.ErrKeyExist
	}
	f.rows[k] = slices.Clone(value.([]prog.UsidVrfTrafficValue))
	return nil
}

func (f *fakeCounterTable) Delete(key any) error {
	k := fakeTableKey(key)
	if _, ok := f.rows[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.rows, k)
	return nil
}

func (f *fakeCounterTable) Iterate() Iterator {
	keys := make([]uint64, 0, len(f.rows))
	for k := range f.rows {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return &fakeCounterIterator{table: f, keys: keys}
}

type fakeCounterIterator struct {
	table *fakeCounterTable
	keys  []uint64
	idx   int
}

func (it *fakeCounterIterator) Next(keyOut, valueOut any) bool {
	if it.idx >= len(it.keys) {
		return false
	}
	k := it.keys[it.idx]
	it.idx++
	*keyOut.(*uint64) = k
	*valueOut.(*[]prog.UsidVrfTrafficValue) = slices.Clone(it.table.rows[k])
	return true
}

func (it *fakeCounterIterator) Err() error { return nil }

// bump adds packets to one CPU's copy of key's row in direction dir, as the
// datapath does.
func (f *fakeCounterTable) bump(t *testing.T, key VRFKey, cpu int, ingress bool, packets, bytes, drops uint64) {
	t.Helper()
	raw, err := uformat.NewVRFKey(key.Block, key.Argument)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := f.rows[uint64(raw)]
	if !ok {
		t.Fatalf("no row for %+v", key)
	}
	c := &row[cpu].Egress
	if ingress {
		c = &row[cpu].Ingress
	}
	c.Packets += packets
	c.Bytes += bytes
	c.DroppedPackets += drops
}

func newTestTrafficTable(table CounterTable) *VRFTrafficTable {
	t := NewVRFTrafficTable(table)
	t.cpus = func() (int, error) { return testTrafficCPUs, nil }
	return t
}

func TestVRFTrafficTable_EnsureKeepsExistingCounts(t *testing.T) {
	fake := newFakeCounterTable()
	traffic := newTestTrafficTable(fake)
	key := VRFKey{Block: testBlock, Argument: 0x21}

	if err := traffic.Ensure(key.Block, key.Argument); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	fake.bump(t, key, 0, true, 3, 300, 1)
	if err := traffic.Ensure(key.Block, key.Argument); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}

	entries, err := traffic.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []VRFTrafficEntry{{VRFKey: key, Ingress: VRFTrafficCounters{Packets: 3, Bytes: 300, DroppedPackets: 1}}}
	if !slices.Equal(entries, want) {
		t.Errorf("List = %+v, want %+v: a repeat Ensure must not reset the row", entries, want)
	}
}

func TestVRFTrafficTable_ListSumsEveryCPU(t *testing.T) {
	fake := newFakeCounterTable()
	traffic := newTestTrafficTable(fake)
	key := VRFKey{Block: testBlock, Argument: 0x21}
	if err := traffic.Ensure(key.Block, key.Argument); err != nil {
		t.Fatal(err)
	}
	fake.bump(t, key, 0, true, 2, 200, 0)
	fake.bump(t, key, 1, true, 5, 500, 1)
	fake.bump(t, key, 0, false, 1, 64, 2)
	fake.bump(t, key, 1, false, 4, 256, 0)

	entries, err := traffic.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []VRFTrafficEntry{{
		VRFKey:  key,
		Ingress: VRFTrafficCounters{Packets: 7, Bytes: 700, DroppedPackets: 1},
		Egress:  VRFTrafficCounters{Packets: 5, Bytes: 320, DroppedPackets: 2},
	}}
	if !slices.Equal(entries, want) {
		t.Errorf("List = %+v, want %+v", entries, want)
	}
}

func TestVRFTrafficTable_RemoveAbsentIsNotError(t *testing.T) {
	traffic := newTestTrafficTable(newFakeCounterTable())
	if err := traffic.Remove(testBlock, 0x21); err != nil {
		t.Errorf("Remove of an absent row: %v, want nil", err)
	}
}

func TestVRFTrafficTable_Sync(t *testing.T) {
	keep := VRFKey{Block: testBlock, Argument: 0x10}
	stale := VRFKey{Block: testBlock, Argument: 0x11}
	racing := VRFKey{Block: testBlock, Argument: 0x12}
	missing := VRFKey{Block: testBlock, Argument: 0x13}

	fake := newFakeCounterTable()
	traffic := newTestTrafficTable(fake)
	for _, k := range []VRFKey{keep, stale, racing} {
		if err := traffic.Ensure(k.Block, k.Argument); err != nil {
			t.Fatal(err)
		}
	}
	fake.bump(t, keep, 0, false, 9, 900, 0)

	want := map[VRFKey]struct{}{keep: {}, missing: {}}
	stillWanted := func(k VRFKey) (bool, error) { return k == racing, nil }
	created, removed, err := traffic.Sync(want, stillWanted)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if created != 1 || removed != 1 {
		t.Errorf("Sync created %d removed %d, want 1 and 1", created, removed)
	}

	got := map[VRFKey]VRFTrafficEntry{}
	entries, err := traffic.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		got[e.VRFKey] = e
	}
	if _, ok := got[stale]; ok {
		t.Error("stale row survived Sync")
	}
	if _, ok := got[racing]; !ok {
		t.Error("row registered while Sync ran was removed")
	}
	if _, ok := got[missing]; !ok {
		t.Error("missing row was not created")
	}
	if got[keep].Egress.Packets != 9 {
		t.Errorf("kept row's egress packets = %d, want 9: Sync must not reset a kept row", got[keep].Egress.Packets)
	}
}

func TestVRFTrafficTable_SyncKeepsRowWhenRecheckFails(t *testing.T) {
	traffic := newTestTrafficTable(newFakeCounterTable())
	if err := traffic.Ensure(testBlock, 0x21); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("lookup failed")
	_, removed, err := traffic.Sync(nil, func(VRFKey) (bool, error) { return false, boom })
	if !errors.Is(err, boom) {
		t.Errorf("Sync error = %v, want it to wrap %v", err, boom)
	}
	if removed != 0 {
		t.Errorf("Sync removed %d rows it could not re-check, want 0", removed)
	}
}

func newTrafficVRFTable() (*VRFTable, *fakeTable, *fakeCounterTable) {
	vrfFake := newFakeTable()
	trafficFake := newFakeCounterTable()
	return NewVRFTable(vrfFake).WithTraffic(newTestTrafficTable(trafficFake)), vrfFake, trafficFake
}

func TestVRFTable_TrafficRowFollowsRegisterAndUnregister(t *testing.T) {
	vrf, _, trafficFake := newTrafficVRFTable()

	if err := vrf.Register(testBlock, 0x21, 7, EgressKindVeth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(trafficFake.rows) != 1 {
		t.Fatalf("traffic rows after Register = %d, want 1", len(trafficFake.rows))
	}
	key := VRFKey{Block: testBlock, Argument: 0x21}
	trafficFake.bump(t, key, 1, true, 4, 400, 0)

	if err := vrf.Register(testBlock, 0x21, 7, EgressKindVeth); err != nil {
		t.Fatalf("re-Register: %v", err)
	}
	entries, err := vrf.traffic.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Ingress.Packets != 4 {
		t.Errorf("traffic after re-Register = %+v, want the 4 counted packets kept", entries)
	}

	if err := vrf.Unregister(testBlock, 0x21); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if len(trafficFake.rows) != 0 {
		t.Errorf("traffic rows after Unregister = %d, want 0", len(trafficFake.rows))
	}
}

func TestVRFTable_RegisterSucceedsWhenTrafficRowFails(t *testing.T) {
	vrf, vrfFake, trafficFake := newTrafficVRFTable()
	trafficFake.createErr = errors.New("map full")

	if err := vrf.Register(testBlock, 0x21, 7, EgressKindVeth); err != nil {
		t.Fatalf("Register = %v, want nil: the counters must never fail a registration", err)
	}
	if vrfFake.len() != 1 {
		t.Errorf("vrf_table rows = %d, want 1", vrfFake.len())
	}
}

func TestVRFTable_SyncTrafficRebuildsRows(t *testing.T) {
	vrf, _, trafficFake := newTrafficVRFTable()
	for _, arg := range []uint16{0x21, 0x22} {
		if err := vrf.Register(testBlock, arg, 7, EgressKindVeth); err != nil {
			t.Fatal(err)
		}
	}
	// A recreated, empty vrf_traffic_counters next to rows that survived.
	clear(trafficFake.rows)
	orphan, err := uformat.NewVRFKey(testBlock, 0x30)
	if err != nil {
		t.Fatal(err)
	}
	trafficFake.rows[uint64(orphan)] = make([]prog.UsidVrfTrafficValue, testTrafficCPUs)

	if err := vrf.SyncTraffic(); err != nil {
		t.Fatalf("SyncTraffic: %v", err)
	}
	entries, err := vrf.traffic.List()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]uint16, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Argument)
	}
	slices.Sort(got)
	if want := []uint16{0x21, 0x22}; !slices.Equal(got, want) {
		t.Errorf("traffic rows after SyncTraffic = %#x, want %#x", got, want)
	}
}

func TestVRFTable_ReconcileRemovesStaleTrafficRow(t *testing.T) {
	vrf, _, trafficFake := newTrafficVRFTable()
	vrf.clock = func() uint64 { return 1 }
	if err := vrf.Register(testBlock, 0x21, 7, EgressKindVeth); err != nil {
		t.Fatal(err)
	}
	if err := vrf.Register(testBlock, 0x22, 7, EgressKindVeth); err != nil {
		t.Fatal(err)
	}

	live := map[VRFKey]struct{}{{Block: testBlock, Argument: 0x22}: {}}
	if _, err := vrf.Reconcile(live, 2); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	keep, err := uformat.NewVRFKey(testBlock, 0x22)
	if err != nil {
		t.Fatal(err)
	}
	if len(trafficFake.rows) != 1 {
		t.Fatalf("traffic rows after Reconcile = %d, want 1", len(trafficFake.rows))
	}
	if _, ok := trafficFake.rows[uint64(keep)]; !ok {
		t.Error("live VRF's traffic row was removed")
	}
}

func TestVRFTable_WithoutTrafficIsUnchanged(t *testing.T) {
	vrf := NewVRFTable(newFakeTable())
	if err := vrf.Register(testBlock, 0x21, 7, EgressKindVeth); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := vrf.SyncTraffic(); err != nil {
		t.Errorf("SyncTraffic without a traffic table = %v, want nil", err)
	}
	if err := vrf.Unregister(testBlock, 0x21); err != nil {
		t.Errorf("Unregister: %v", err)
	}
}

// A VRF registered between Sync's check and its delete has already found its
// row present, so Sync must put the row back.
func TestVRFTrafficTable_SyncRestoresRowRegisteredDuringDelete(t *testing.T) {
	fake := newFakeCounterTable()
	traffic := newTestTrafficTable(fake)
	if err := traffic.Ensure(testBlock, 0x21); err != nil {
		t.Fatal(err)
	}
	calls := 0
	stillWanted := func(VRFKey) (bool, error) {
		calls++
		return calls > 1, nil
	}
	if _, _, err := traffic.Sync(nil, stillWanted); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(fake.rows) != 1 {
		t.Errorf("traffic rows = %d, want the row restored for the VRF registered mid-delete", len(fake.rows))
	}
}
