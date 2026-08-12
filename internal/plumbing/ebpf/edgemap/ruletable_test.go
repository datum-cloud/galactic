// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemap

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// fakeTable is an in-memory Table, letting RuleTable's register/
// unregister/reconcile logic be exercised without a kernel or root
// privileges -- same pattern as internal/plumbing/ebpf/usidmap's identical
// fake table.
type fakeTable struct {
	entries map[edgeprog.EdgenatRuleKey]edgeprog.EdgenatRuleValue
}

func newFakeTable() *fakeTable {
	return &fakeTable{entries: make(map[edgeprog.EdgenatRuleKey]edgeprog.EdgenatRuleValue)}
}

func (f *fakeTable) Put(key, value any) error {
	f.entries[key.(edgeprog.EdgenatRuleKey)] = value.(edgeprog.EdgenatRuleValue)
	return nil
}

func (f *fakeTable) Lookup(key, valueOut any) error {
	v, ok := f.entries[key.(edgeprog.EdgenatRuleKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*edgeprog.EdgenatRuleValue) = v
	return nil
}

func (f *fakeTable) Delete(key any) error {
	k := key.(edgeprog.EdgenatRuleKey)
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeTable) Iterate() Iterator {
	keys := make([]edgeprog.EdgenatRuleKey, 0, len(f.entries))
	for k := range f.entries {
		keys = append(keys, k)
	}
	return &fakeIterator{table: f, keys: keys}
}

type fakeIterator struct {
	table *fakeTable
	keys  []edgeprog.EdgenatRuleKey
	i     int
}

func (it *fakeIterator) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.keys) {
		return false
	}
	k := it.keys[it.i]
	it.i++
	*keyOut.(*edgeprog.EdgenatRuleKey) = k
	*valueOut.(*edgeprog.EdgenatRuleValue) = it.table.entries[k]
	return true
}

func (it *fakeIterator) Err() error { return nil }

var _ Table = (*fakeTable)(nil)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%q): %v", s, err)
	}
	return a
}

func testKey(t *testing.T) RuleKey {
	return RuleKey{Proto: 6, VPort: 443, VIP: mustAddr(t, "2001:db8:1::10")}
}

func testBackend(t *testing.T) Backend {
	return Backend{
		Addr: mustAddr(t, "fd00:10:1::20"),
		Port: 8443,
		USID: mustAddr(t, "2001:db8:2::1"),
	}
}

func TestRuleTable_RegisterGetRoundTrip(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	key, backend := testKey(t), testBackend(t)

	if err := rt.Register(key, []Backend{backend}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok, err := rt.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get: entry not found after Register")
	}
	if len(got.Backends) != 1 || got.Backends[0] != backend {
		t.Errorf("Get: backends = %+v, want [%+v]", got.Backends, backend)
	}
}

func TestRuleTable_RegisterRejectsEmptyBackends(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	if err := rt.Register(testKey(t), nil); err == nil {
		t.Error("Register with no backends: want error, got nil")
	}
}

func TestRuleTable_RegisterRejectsTooManyBackends(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	backends := make([]Backend, MaxBackends+1)
	for i := range backends {
		backends[i] = testBackend(t)
	}
	if err := rt.Register(testKey(t), backends); err == nil {
		t.Error("Register with MaxBackends+1 backends: want error, got nil")
	}
}

func TestRuleTable_RegisterRejectsIPv4Backend(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	backend := testBackend(t)
	backend.Addr = netip.MustParseAddr("192.0.2.1")
	if err := rt.Register(testKey(t), []Backend{backend}); err == nil {
		t.Error("Register with an IPv4 backend address: want error, got nil")
	}
}

func TestRuleTable_UnregisterIsIdempotent(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	key := testKey(t)
	if err := rt.Unregister(key); err != nil {
		t.Fatalf("Unregister on an absent key: %v, want nil", err)
	}
	if err := rt.Register(key, []Backend{testBackend(t)}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := rt.Unregister(key); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if err := rt.Unregister(key); err != nil {
		t.Fatalf("second Unregister on an already-absent key: %v, want nil", err)
	}
	if _, ok, _ := rt.Get(key); ok {
		t.Error("entry still present after Unregister")
	}
}

func TestRuleTable_GetMissingReturnsFalseNotError(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	_, ok, err := rt.Get(testKey(t))
	if err != nil {
		t.Fatalf("Get on an absent key: %v, want nil error", err)
	}
	if ok {
		t.Error("Get on an absent key: ok = true, want false")
	}
}

func TestRuleTable_List(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	key1 := testKey(t)
	key2 := RuleKey{Proto: 17, VPort: 53, VIP: mustAddr(t, "2001:db8:1::11")}

	if err := rt.Register(key1, []Backend{testBackend(t)}); err != nil {
		t.Fatalf("Register key1: %v", err)
	}
	if err := rt.Register(key2, []Backend{testBackend(t)}); err != nil {
		t.Fatalf("Register key2: %v", err)
	}

	entries, err := rt.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List: len = %d, want 2", len(entries))
	}
}

func TestRuleTable_ReconcileRemovesStaleNotLive(t *testing.T) {
	var fakeClock uint64
	rt := NewRuleTable(newFakeTable())
	rt.clock = func() uint64 { return fakeClock }

	liveKey := testKey(t)
	staleKey := RuleKey{Proto: 17, VPort: 53, VIP: mustAddr(t, "2001:db8:1::11")}

	fakeClock = 100
	if err := rt.Register(liveKey, []Backend{testBackend(t)}); err != nil {
		t.Fatalf("Register liveKey: %v", err)
	}
	if err := rt.Register(staleKey, []Backend{testBackend(t)}); err != nil {
		t.Fatalf("Register staleKey: %v", err)
	}

	// The cutoff snapshot is taken strictly after both entries were
	// written (generation 100 < cutoff 150), matching the real ordering
	// contract: capture Generation() immediately before listing the live
	// NetworkRule CRDs, i.e. after whatever already-registered state
	// exists, not before it.
	fakeClock = 150
	cutoff := rt.Generation()
	fakeClock = 200

	removed, err := rt.Reconcile(map[RuleKey]struct{}{liveKey: {}}, cutoff)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(removed) != 1 || removed[0].RuleKey != staleKey {
		t.Errorf("Reconcile removed = %+v, want exactly [staleKey]", removed)
	}
	if _, ok, _ := rt.Get(liveKey); !ok {
		t.Error("Reconcile removed the live entry")
	}
	if _, ok, _ := rt.Get(staleKey); ok {
		t.Error("Reconcile left the stale entry in place")
	}
}

// TestRuleTable_ReconcileSparesRecentGeneration covers the crash-safety
// case doc.go describes: an entry written *after* the caller's live
// snapshot's cutoff must survive even though it's absent from live --
// deleting it would race a fresh Register that just hasn't made it into
// the caller's live set yet.
func TestRuleTable_ReconcileSparesRecentGeneration(t *testing.T) {
	var fakeClock uint64
	rt := NewRuleTable(newFakeTable())
	rt.clock = func() uint64 { return fakeClock }

	cutoff := rt.Generation() // 0

	fakeClock = 50 // written AFTER the cutoff snapshot was taken
	recentKey := testKey(t)
	if err := rt.Register(recentKey, []Backend{testBackend(t)}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	removed, err := rt.Reconcile(map[RuleKey]struct{}{}, cutoff)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("Reconcile removed = %+v, want none (generation %d >= cutoff %d)", removed, fakeClock, cutoff)
	}
	if _, ok, _ := rt.Get(recentKey); !ok {
		t.Error("Reconcile removed a recently-written entry it should have spared")
	}
}

func TestRuleTable_RegisterOverwritesExistingKey(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	key := testKey(t)
	b1 := testBackend(t)
	b2 := Backend{Addr: mustAddr(t, "fd00:10:1::99"), Port: 9999, USID: mustAddr(t, "2001:db8:2::2")}

	if err := rt.Register(key, []Backend{b1}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := rt.Register(key, []Backend{b2}); err != nil {
		t.Fatalf("second Register: %v", err)
	}

	got, ok, err := rt.Get(key)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if len(got.Backends) != 1 || got.Backends[0] != b2 {
		t.Errorf("Get after overwrite: backends = %+v, want [%+v]", got.Backends, b2)
	}
}

// TestRuleTable_RegisterPreservesHitCounters verifies Register's
// read-modify-write behavior (Phase E): re-registering an existing key
// (e.g. every controller reconcile pass, per Engine.Reconcile's "apply
// everything in desired" convention) must not zero the datapath-maintained
// Packets/Bytes/DroppedPackets/LastSeenNs counters, only Backends/
// Generation.
func TestRuleTable_RegisterPreservesHitCounters(t *testing.T) {
	table := newFakeTable()
	rt := NewRuleTable(table)
	key := testKey(t)

	if err := rt.Register(key, []Backend{testBackend(t)}); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// Simulate the datapath having handled traffic between reconciles by
	// writing counters directly into the fake table's backing map, the
	// same way edgenat.c's __sync_fetch_and_add calls would in the real
	// kernel map.
	wireKey, err := toWireKey(key)
	if err != nil {
		t.Fatalf("toWireKey: %v", err)
	}
	entry := table.entries[wireKey]
	entry.Packets = 42
	entry.Bytes = 4096
	entry.DroppedPackets = 3
	entry.LastSeenNs = 123456789
	table.entries[wireKey] = entry

	// Re-register with a different backend, exactly as a later
	// convergence pass would (e.g. a backend Pod rescheduled).
	b2 := Backend{Addr: mustAddr(t, "fd00:10:1::99"), Port: 9999, USID: mustAddr(t, "2001:db8:2::2")}
	if err := rt.Register(key, []Backend{b2}); err != nil {
		t.Fatalf("second Register: %v", err)
	}

	got, ok, err := rt.Get(key)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.Packets != 42 {
		t.Errorf("Packets after re-register = %d, want 42 (preserved)", got.Packets)
	}
	if got.Bytes != 4096 {
		t.Errorf("Bytes after re-register = %d, want 4096 (preserved)", got.Bytes)
	}
	if got.DroppedPackets != 3 {
		t.Errorf("DroppedPackets after re-register = %d, want 3 (preserved)", got.DroppedPackets)
	}
	if got.LastSeenNs != 123456789 {
		t.Errorf("LastSeenNs after re-register = %d, want 123456789 (preserved)", got.LastSeenNs)
	}
	if len(got.Backends) != 1 || got.Backends[0] != b2 {
		t.Errorf("Backends after re-register = %+v, want [%+v] (updated)", got.Backends, b2)
	}
}

// TestRuleTable_RegisterOnFreshKeyStartsCountersAtZero verifies a brand
// new key's counters start at zero, not garbage from an unrelated
// previous lookup failure.
func TestRuleTable_RegisterOnFreshKeyStartsCountersAtZero(t *testing.T) {
	rt := NewRuleTable(newFakeTable())
	key := testKey(t)

	if err := rt.Register(key, []Backend{testBackend(t)}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok, err := rt.Get(key)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.Packets != 0 || got.Bytes != 0 || got.DroppedPackets != 0 || got.LastSeenNs != 0 {
		t.Errorf("fresh key counters = %+v, want all zero", got)
	}
}

func TestBeU16_IsItsOwnInverse(t *testing.T) {
	for _, v := range []uint16{0, 1, 443, 8443, 65535} {
		if got := beU16(beU16(v)); got != v {
			t.Errorf("beU16(beU16(%d)) = %d, want %d", v, got, v)
		}
	}
}

func TestFakeTable_LookupMissingReturnsErrKeyNotExist(t *testing.T) {
	f := newFakeTable()
	var v edgeprog.EdgenatRuleValue
	err := f.Lookup(edgeprog.EdgenatRuleKey{}, &v)
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("Lookup on empty fakeTable: err = %v, want ebpf.ErrKeyNotExist", err)
	}
}
