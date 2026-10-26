// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemap

import (
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

func TestRangeTableBoundedAtomicIntervals(t *testing.T) {
	raw := newFakeMap[edgeprog.EdgedsrVipKey, edgeprog.EdgedsrVipRangeValue]()
	table := NewRangeTable(raw)
	vip := netip.MustParseAddr("2001:db8::1")
	a := VIPKey{Proto: 17, VPort: 10000, VIP: vip}
	b := VIPKey{Proto: 17, VPort: 11000, VIP: vip}
	for _, v := range []struct {
		k   VIPKey
		end uint16
	}{{a, 10127}, {b, 11127}} {
		if err := table.Register(v.k, v.end, 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := table.Register(VIPKey{Proto: 17, VPort: 10100, VIP: vip}, 10200, 4); err == nil {
		t.Fatal("overlap accepted")
	}
	if err := table.Register(a, 10031, 5); err != nil {
		t.Fatal(err)
	}
	key, _ := rangeKey(a)
	var got edgeprog.EdgedsrVipRangeValue
	if err := raw.Lookup(key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 2 || got.Ranges[0].End != 10031 || got.Ranges[0].Generation != 5 || got.Ranges[1].Start != 11000 {
		t.Fatalf("bad snapshot: %+v", got)
	}
	if err := table.Remove(a); err != nil {
		t.Fatal(err)
	}
	if err := raw.Lookup(key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 1 || got.Ranges[0].Start != 11000 {
		t.Fatalf("sibling lost: %+v", got)
	}
}

func TestRangeTableCapacity(t *testing.T) {
	raw := newFakeMap[edgeprog.EdgedsrVipKey, edgeprog.EdgedsrVipRangeValue]()
	table := NewRangeTable(raw)
	vip := netip.MustParseAddr("2001:db8::1")
	for i := uint16(1); i <= MaxRangesPerVIP; i++ {
		if err := table.Register(VIPKey{Proto: 17, VPort: i * 100, VIP: vip}, i*100+10, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := table.Register(VIPKey{Proto: 17, VPort: 1700, VIP: vip}, 1710, 1); err == nil {
		t.Fatal("capacity overflow accepted")
	}
}

func TestWideRangeUsesOneDescriptor(t *testing.T) {
	raw := newFakeMap[edgeprog.EdgedsrVipKey, edgeprog.EdgedsrVipRangeValue]()
	table := NewRangeTable(raw)
	key := VIPKey{Proto: 17, VPort: 10000, VIP: netip.MustParseAddr("2001:db8::1")}
	if err := table.Register(key, 60000, 9); err != nil {
		t.Fatal(err)
	}
	wire, _ := rangeKey(key)
	var value edgeprog.EdgedsrVipRangeValue
	if err := raw.Lookup(wire, &value); err != nil {
		t.Fatal(err)
	}
	if len(raw.entries) != 1 || value.Count != 1 || value.Ranges[0].End != 60000 {
		t.Fatalf("not compact: %+v", value)
	}
}

func TestOwnedVIPConvergencePreservesBlock(t *testing.T) {
	raw := newFakeMap[edgeprog.EdgedsrVipAddrKey, edgeprog.EdgedsrVipOwnedValue]()
	addr := netip.MustParseAddr("2001:db8::1")
	if err := ReplaceOwnedVIPs(raw, []netip.Addr{addr}, 1); err != nil {
		t.Fatal(err)
	}
	key := edgeprog.EdgedsrVipAddrKey{Vip: addr.As16()}
	if raw.entries[key].Blocked != 1 {
		t.Fatal("new VIP did not start blocked")
	}
	if err := ReplaceOwnedVIPs(raw, []netip.Addr{addr}, 2); err != nil {
		t.Fatal(err)
	}
	if raw.entries[key].Blocked != 1 {
		t.Fatal("ownership refresh opened blocked VIP")
	}
	if err := SetBlockedVIPs(raw, nil); err != nil {
		t.Fatal(err)
	}
	if raw.entries[key].Blocked != 0 {
		t.Fatal("successful convergence did not unblock")
	}
}

func TestRangeAndSingletonShareReturnAddressLifetime(t *testing.T) {
	exact, groups, addrs := newFakeTable(), newFakeTable(), newFakeAddrTable()
	stats, returns := newFakeStatsTable(), newFakeReturnStatsTable()
	scalar := NewVIPTable(exact, stats, addrs, returns).WithPeerTable(groups)
	ranged := NewVIPTable(groups, stats, addrs, returns).WithPeerTable(exact)
	key := testKey(t)
	sibling := key
	sibling.Proto = 17
	sibling.VPort = 10000
	backend := []Backend{testBackend(t)}
	if err := scalar.Register(key, 0, backend, [MaglevTableSize]byte{}); err != nil {
		t.Fatal(err)
	}
	if err := ranged.Register(sibling, 0, backend, [MaglevTableSize]byte{}); err != nil {
		t.Fatal(err)
	}
	if err := scalar.Unregister(key); err != nil {
		t.Fatal(err)
	}
	if len(addrs.entries) != 1 {
		t.Fatal("removing singleton broke range return traffic")
	}
	if err := ranged.Unregister(sibling); err != nil {
		t.Fatal(err)
	}
	if len(addrs.entries) != 0 {
		t.Fatal("final rule retained return address")
	}
}
