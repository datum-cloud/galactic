// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import (
	"net/netip"
	"sort"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
)

func testConnKey() ConnKey {
	return ConnKey{
		Proto:     17,
		TenantArg: 0x123,
		Sport:     40000,
		Dport:     443,
		Saddr:     netip.MustParseAddr("fd20:60::5"),
		Daddr:     netip.MustParseAddr("2001:db8:9998::1"),
	}
}

func testConnEntry() ConnEntry {
	return ConnEntry{
		ConnKey:     testConnKey(),
		BackendAddr: netip.MustParseAddr("fd20:60::5"),
		BackendPort: 40000,
		DestAddr:    netip.MustParseAddr("2001:db8:9998::1"),
		DestPort:    443,
		ShardPort:   35000,
		BackendUSID: netip.MustParseAddr("fc00:3:4::a1b2"),
		Proto:       17,
	}
}

// connValueFromEntry is the inverse of fromWireConnValue -- test-only,
// since ConnTable itself is deliberately read-only (see doc.go) and
// exposes no Put/Register method to seed test data through.
func connValueFromEntry(e ConnEntry) nat66prog.Nat66ConnValue {
	return nat66prog.Nat66ConnValue{
		BackendAddr: e.BackendAddr.As16(),
		BackendPort: beU16(e.BackendPort),
		DestAddr:    e.DestAddr.As16(),
		DestPort:    beU16(e.DestPort),
		ShardPort:   beU16(e.ShardPort),
		BackendUsid: e.BackendUSID.As16(),
		Proto:       e.Proto,
	}
}

// putEntry writes e directly through the wire conversion helpers.
func putEntry(t *testing.T, table Table, e ConnEntry) {
	t.Helper()
	wireKey, err := toWireConnKey(e.ConnKey)
	if err != nil {
		t.Fatalf("toWireConnKey: %v", err)
	}
	if err := table.Put(wireKey, connValueFromEntry(e)); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func TestConnTable_GetHit(t *testing.T) {
	fake := newFakeTable()
	entry := testConnEntry()
	putEntry(t, fake, entry)

	table := NewConnTable(fake)
	got, ok, err := table.Get(entry.ConnKey)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatal("Get() ok = false, want true")
	}
	if got != entry {
		t.Errorf("Get() = %+v, want %+v", got, entry)
	}
}

func TestConnTable_GetMiss(t *testing.T) {
	table := NewConnTable(newFakeTable())
	got, ok, err := table.Get(testConnKey())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok {
		t.Errorf("Get() ok = true, want false for an absent key; got %+v", got)
	}
}

func TestConnTable_GetRejectsIPv4Key(t *testing.T) {
	table := NewConnTable(newFakeTable())
	key := testConnKey()
	key.Saddr = netip.MustParseAddr("203.0.113.1")

	_, _, err := table.Get(key)
	if err == nil {
		t.Fatal("Get() error = nil, want an error for a non-native-IPv6 key address")
	}
}

func TestConnTable_List(t *testing.T) {
	fake := newFakeTable()

	first := testConnEntry()
	second := testConnEntry()
	second.Sport = 40001
	second.ShardPort = 35001

	putEntry(t, fake, first)
	putEntry(t, fake, second)

	table := NewConnTable(fake)
	entries, err := table.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List() returned %d entries, want 2", len(entries))
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Sport < entries[j].Sport })
	if entries[0] != first {
		t.Errorf("entries[0] = %+v, want %+v", entries[0], first)
	}
	if entries[1] != second {
		t.Errorf("entries[1] = %+v, want %+v", entries[1], second)
	}
}

func TestConnTable_ListEmpty(t *testing.T) {
	table := NewConnTable(newFakeTable())
	entries, err := table.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List() = %d entries, want 0 on an empty table", len(entries))
	}
}
