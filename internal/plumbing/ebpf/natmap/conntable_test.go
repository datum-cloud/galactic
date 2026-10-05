// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natmap

import (
	"errors"
	"net/netip"
	"sort"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
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

		BackendTenantArg: 0x123,
		State:            natprog.SessionTCPEstablished,
		LastSeen:         4242,
	}
}

// connValueFromEntry is the inverse of fromWireConnValue -- test-only,
// since ConnTable itself is deliberately read-only (see doc.go) and
// exposes no Put/Register method to seed test data through.
func connValueFromEntry(e ConnEntry) natprog.NatConnValue {
	return natprog.NatConnValue{
		BackendAddr: e.BackendAddr.As16(),
		BackendPort: beU16(e.BackendPort),
		DestAddr:    e.DestAddr.As16(),
		DestPort:    beU16(e.DestPort),
		ShardPort:   beU16(e.ShardPort),
		BackendUsid: e.BackendUSID.As16(),
		Proto:       e.Proto,
		TenantArg:   e.BackendTenantArg,
		State:       e.State,
		LastSeen:    e.LastSeen,
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

// abortingTable is a table whose walk yields its rows and then fails, the way
// a walk the datapath's evictions keep restarting ends.
type abortingTable struct{ *fakeTable }

func (a abortingTable) Iterate() Iterator {
	return &abortingIterator{Iterator: a.fakeTable.Iterate()}
}

type abortingIterator struct{ Iterator }

func (*abortingIterator) Err() error { return ebpf.ErrIterationAborted }

// sessionRow builds a reverse row: no encapsulation source, as the datapath
// writes one. destPort, state and lastSeen are the fields liveness reads.
func sessionRow(family, proto uint8, shardPort, destPort uint16, state uint8, lastSeen uint32) ConnEntry {
	e := testConnEntry()
	e.Family = family
	e.Proto = proto
	e.ConnKey.Proto = proto
	e.TenantArg = 0
	e.Sport = 0
	e.Dport = shardPort
	e.DestPort = destPort
	e.State = state
	e.LastSeen = lastSeen
	return e
}

func TestConnTable_CountSessions(t *testing.T) {
	const now uint32 = 100_000
	est := natprog.SessionTCPEstablished
	closing := natprog.SessionTCPEstablished | natprog.SessionTCPClosing

	tests := []struct {
		name     string
		proto    uint8
		destPort uint16
		state    uint8
		age      uint32
		live     bool
	}{
		{"udp live", 17, 443, 0, natprog.TimeoutUDP, true},
		{"udp expired", 17, 443, 0, natprog.TimeoutUDP + 1, false},
		{"udp dns live", 17, 53, 0, natprog.TimeoutUDPDNS, true},
		{"udp dns expired", 17, 53, 0, natprog.TimeoutUDPDNS + 1, false},
		{"tcp established live", 6, 443, est, natprog.TimeoutTCPEstablished, true},
		{"tcp established expired", 6, 443, est, natprog.TimeoutTCPEstablished + 1, false},
		{"tcp transitory live", 6, 443, 0, natprog.TimeoutTCPTransitory, true},
		{"tcp transitory expired", 6, 443, 0, natprog.TimeoutTCPTransitory + 1, false},
		{"tcp closing expired", 6, 443, closing, natprog.TimeoutTCPTransitory + 1, false},
		{"icmp live", 58, 0, 0, natprog.TimeoutICMP, true},
		{"icmp expired", 58, 0, 0, natprog.TimeoutICMP + 1, false},
	}

	for _, family := range []uint8{natprog.FamilyIPv6, natprog.FamilyIPv4} {
		for _, tt := range tests {
			t.Run(familyName(family)+"/"+tt.name, func(t *testing.T) {
				fake := newFakeTable()
				putEntry(t, fake, sessionRow(family, tt.proto, 35000, tt.destPort, tt.state, now-tt.age))

				counts, err := NewConnTable(fake).CountSessions(now)
				if err != nil {
					t.Fatalf("CountSessions: %v", err)
				}
				want := 0
				if tt.live {
					want = 1
				}
				key := SessionKey{Family: family, Proto: sessionProto(tt.proto)}
				if got := counts.Live[key]; got != want {
					t.Errorf("Live[%v] = %d, want %d", key, got, want)
				}
				if counts.Rows[family] != 1 {
					t.Errorf("Rows[%d] = %d, want 1 whether or not the session expired", family, counts.Rows[family])
				}
				if !counts.HasReverse || counts.OldestAge != tt.age {
					t.Errorf("OldestAge = %d (HasReverse %t), want %d", counts.OldestAge, counts.HasReverse, tt.age)
				}
			})
		}
	}
}

func familyName(family uint8) string {
	if family == natprog.FamilyIPv4 {
		return "nat64"
	}
	return "nat66"
}

func TestConnTable_CountSessionsMixedTable(t *testing.T) {
	const now uint32 = 100_000
	fake := newFakeTable()

	// Two live sessions and three expired ones, as a busy DNS client leaves
	// the table.
	putEntry(t, fake, sessionRow(natprog.FamilyIPv6, 17, 35000, 53, 0, now-5))
	putEntry(t, fake, sessionRow(natprog.FamilyIPv6, 17, 35001, 53, 0, now-3600))
	putEntry(t, fake, sessionRow(natprog.FamilyIPv6, 17, 35002, 53, 0, now-600))
	putEntry(t, fake, sessionRow(natprog.FamilyIPv4, 6, 35003, 443, natprog.SessionTCPEstablished, now-7000))
	putEntry(t, fake, sessionRow(natprog.FamilyIPv4, 1, 35004, 0, 0, now-61))

	// A forward row, keyed by its encapsulation source, whose last_seen is
	// from when it was written: never live, never the oldest.
	fwd := testConnEntry()
	fwd.Family = natprog.FamilyIPv6
	fwd.EncapSrc = netip.MustParseAddr("fc00:3:4::1")
	fwd.LastSeen = 1
	putEntry(t, fake, fwd)

	counts, err := NewConnTable(fake).CountSessions(now)
	if err != nil {
		t.Fatalf("CountSessions: %v", err)
	}
	wantLive := map[SessionKey]int{
		{Family: natprog.FamilyIPv6, Proto: SessionProtoUDP}: 1,
		{Family: natprog.FamilyIPv4, Proto: SessionProtoTCP}: 1,
	}
	if len(counts.Live) != len(wantLive) {
		t.Errorf("Live = %v, want %v", counts.Live, wantLive)
	}
	for k, v := range wantLive {
		if counts.Live[k] != v {
			t.Errorf("Live[%v] = %d, want %d", k, counts.Live[k], v)
		}
	}
	if counts.Rows[natprog.FamilyIPv6] != 4 || counts.Rows[natprog.FamilyIPv4] != 2 {
		t.Errorf("Rows = %v, want 4 IPv6 and 2 IPv4", counts.Rows)
	}
	if counts.OldestAge != 7000 {
		t.Errorf("OldestAge = %d, want 7000 from the reverse rows alone", counts.OldestAge)
	}

	counts, err = NewConnTable(abortingTable{fake}).CountSessions(now)
	if !errors.Is(err, ebpf.ErrIterationAborted) {
		t.Fatalf("CountSessions on an aborted walk: err = %v, want ErrIterationAborted", err)
	}
	if counts.Rows[natprog.FamilyIPv6] != 4 || counts.Rows[natprog.FamilyIPv4] != 2 {
		t.Errorf("rows from an aborted walk = %v, want the rows seen before it ended", counts.Rows)
	}
}

func TestConnTable_CountSessionsClockWrap(t *testing.T) {
	// The clock wrapped 10 s ago; the row was stamped 20 s before the wrap.
	const now uint32 = 10
	fake := newFakeTable()
	putEntry(t, fake, sessionRow(natprog.FamilyIPv6, 17, 35000, 53, 0, ^uint32(0)-19))

	counts, err := NewConnTable(fake).CountSessions(now)
	if err != nil {
		t.Fatalf("CountSessions: %v", err)
	}
	if counts.OldestAge != 30 {
		t.Errorf("OldestAge = %d, want 30 across the wrap", counts.OldestAge)
	}
	if got := counts.Live[SessionKey{Family: natprog.FamilyIPv6, Proto: SessionProtoUDP}]; got != 1 {
		t.Errorf("a 30 s old DNS session across the wrap: live = %d, want 1", got)
	}
}

func TestConnTable_CountSessionsEmpty(t *testing.T) {
	counts, err := NewConnTable(newFakeTable()).CountSessions(1)
	if err != nil {
		t.Fatalf("CountSessions: %v", err)
	}
	if counts.HasReverse || len(counts.Rows) != 0 || len(counts.Live) != 0 {
		t.Errorf("counts on an empty table = %+v, want nothing", counts)
	}
}
