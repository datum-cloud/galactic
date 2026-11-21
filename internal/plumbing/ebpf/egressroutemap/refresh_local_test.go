// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"maps"
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// reachableLocators makes every SID on one of alive's locators resolve,
// whatever its Function or Argument, and every other SID fail.
func reachableLocators(t *testing.T, alive ...netip.Addr) {
	t.Helper()
	ok := map[uformat.LocatorKey]bool{}
	for _, a := range alive {
		k, err := uformat.LocatorKeyFromAddr(a)
		if err != nil {
			t.Fatal(err)
		}
		ok[k] = true
	}
	prev := resolveLinkAndL2Fn
	resolveLinkAndL2Fn = func(sid net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		addr, _ := netip.AddrFromSlice(sid)
		if k, err := uformat.LocatorKeyFromAddr(addr.Unmap()); err == nil && ok[k] {
			return 1, dpShardMAC, dpUplinkMAC, nil
		}
		return 0, nil, nil, errors.New("unreachable in this test")
	}
	t.Cleanup(func() { resolveLinkAndL2Fn = prev })
}

func shardIPs(sids ...netip.Addr) []net.IP {
	out := make([]net.IP, 0, len(sids))
	for _, s := range sids {
		out = append(out, net.IP(s.AsSlice()))
	}
	return out
}

func entryAt(t *testing.T, tbl *EgressRouteTable, table uint32, prefix *net.IPNet) prog.UsidEgressRouteValue {
	t.Helper()
	key, err := buildKey(table, prefix)
	if err != nil {
		t.Fatal(err)
	}
	value, err := lookupRaw(tbl, key)
	if err != nil {
		t.Fatalf("no entry for table %d %s: %v", table, prefix, err)
	}
	return value
}

// putRaw writes value for prefix in table 1 directly, as a writer outside
// this package's API would.
func putRaw(t *testing.T, tbl *EgressRouteTable, prefix *net.IPNet, value prog.UsidEgressRouteValue) {
	t.Helper()
	key, err := buildKey(1, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := tbl.table.Put(key, value); err != nil {
		t.Fatal(err)
	}
}

func snapshotTable(f *fakeTable) map[any]any {
	return maps.Clone(f.entries)
}

// TestRefreshOrderedPlacesClassRoutesOnTheLocalShard checks ordered mode with
// egress_local_shard rows: a table with a row whose shard comes first moves
// its class routes onto the local shard, keeping the Argument, and a table
// with no row keeps its shard.
func TestRefreshOrderedPlacesClassRoutesOnTheLocalShard(t *testing.T) {
	local, remote, peer := shardSID(0x10), shardSID(0x11), shardSID(0x20)
	reachableLocators(t, remote, peer)
	tbl := NewEgressRouteTable(newFakeTable())
	for table, arg := range map[uint32]uint16{1: 0x123, 2: 0x456} {
		if err := tbl.Register(table, DefaultPrefix, tenantSID(remote, arg)); err != nil {
			t.Fatal(err)
		}
		if err := tbl.Register(table, nspNet(), tenantSID(remote, arg)); err != nil {
			t.Fatal(err)
		}
	}
	tenant := mustCIDR(t, "fd00:1::/64")
	// A tenant route toward another node, which is no shard.
	if err := tbl.Register(1, tenant, tenantSID(peer, 0x77)); err != nil {
		t.Fatal(err)
	}
	before2 := entryAt(t, tbl, 2, DefaultPrefix)

	result, err := tbl.Refresh(nil, shardIPs(local, remote),
		WithLocalShards(map[uint32]LocalShard{1: {ShardSID: local, PairIfindex: 9}}))
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalNAT != 2 {
		t.Errorf("result %+v, want 2 class routes moved onto the local shard", result)
	}
	for _, p := range []*net.IPNet{DefaultPrefix, nspNet()} {
		if v := entryAt(t, tbl, 1, p); v != localClassRoute(0x123) {
			t.Errorf("table 1 %s = %+v, want a PassThroughLocalNAT entry with Argument 0x123", p, v)
		}
		if arg, ours := localClassArgument(mustKey(t, 1, p), entryAt(t, tbl, 1, p)); !ours || arg != 0x123 {
			t.Errorf("table 1 %s: Argument %#x ours %t", p, arg, ours)
		}
	}
	if v := entryAt(t, tbl, 2, DefaultPrefix); v != before2 {
		t.Errorf("table 2 (no row) ::/0 = %+v, want unchanged %+v", v, before2)
	}
	if v := entryAt(t, tbl, 1, tenant); v.LinkIfindex == 0 {
		t.Errorf("table 1 tenant route became a pass-through: %+v", v)
	}
}

func mustKey(t *testing.T, table uint32, prefix *net.IPNet) prog.UsidEgressRouteKey {
	t.Helper()
	k, err := buildKey(table, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRefreshOrderedKeepsAShardAheadOfTheLocalOne(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachableLocators(t, remote)
	tbl := NewEgressRouteTable(newFakeTable())
	if err := tbl.Register(1, DefaultPrefix, tenantSID(remote, 0x123)); err != nil {
		t.Fatal(err)
	}
	before := entryAt(t, tbl, 1, DefaultPrefix)
	result, err := tbl.Refresh(nil, shardIPs(remote, local),
		WithLocalShards(map[uint32]LocalShard{1: {ShardSID: local}}))
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalNAT != 0 || entryAt(t, tbl, 1, DefaultPrefix) != before {
		t.Errorf("result %+v, entry %+v; want the route left on the remote shard listed first",
			result, entryAt(t, tbl, 1, DefaultPrefix))
	}
}

func TestRefreshOrderedRestoresWhenTheRowGoes(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachableLocators(t, remote)
	tbl := NewEgressRouteTable(newFakeTable())
	putRaw(t, tbl, DefaultPrefix, localClassRoute(0x123))

	result, err := tbl.Refresh(nil, shardIPs(local, remote), WithLocalShards(nil))
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalRestored != 1 {
		t.Errorf("result %+v, want one route restored", result)
	}
	v := entryAt(t, tbl, 1, DefaultPrefix)
	if v.LinkIfindex == 0 || net.IP(v.Sid[:]).String() != tenantSID(remote, 0x123).String() {
		t.Errorf("restored entry %+v, want the remote shard with Argument 0x123", v)
	}
}

func TestRefreshOrderedKeepsTheLocalRouteWhileTheRowStays(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachableLocators(t, remote)
	tbl := NewEgressRouteTable(newFakeTable())
	putRaw(t, tbl, DefaultPrefix, localClassRoute(0x123))
	result, err := tbl.Refresh(nil, shardIPs(local, remote),
		WithLocalShards(map[uint32]LocalShard{1: {ShardSID: local}}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Refreshed != 0 || entryAt(t, tbl, 1, DefaultPrefix) != localClassRoute(0x123) {
		t.Errorf("result %+v; want the local route kept as it was", result)
	}
}

func TestRefreshOrderedMovesASentinelOntoTheLocalShard(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachableLocators(t, remote)
	tbl := NewEgressRouteTable(newFakeTable())
	if err := tbl.RegisterGroup(1, DefaultPrefix, 0, 0x123); err != nil {
		t.Fatal(err)
	}
	result, err := tbl.Refresh(nil, shardIPs(local, remote),
		WithLocalShards(map[uint32]LocalShard{1: {ShardSID: local}}))
	if err != nil {
		t.Fatal(err)
	}
	if result.LocalNAT != 1 || result.SentinelRoutes() != 0 ||
		entryAt(t, tbl, 1, DefaultPrefix) != localClassRoute(0x123) {
		t.Errorf("result %+v, entry %+v; want the sentinel moved onto the local shard",
			result, entryAt(t, tbl, 1, DefaultPrefix))
	}
}

func TestRefreshHashedMovesALocalRouteOntoItsGroup(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	putRaw(t, tbl, nspNet(), localClassRoute(0x123))
	result, err := tbl.Refresh(nil, shardIPs(shardSID(0x11)), WithShardGroups(byClass),
		WithLocalShards(map[uint32]LocalShard{1: {ShardSID: shardSID(0x10)}}))
	if err != nil {
		t.Fatal(err)
	}
	v := entryAt(t, tbl, 1, nspNet())
	if g, a := sentinelGroup(v); !isGroupSentinel(v) || g != 1 || a != 0x123 || result.GroupRoutes[1] != 1 {
		t.Errorf("entry %+v (group %d arg %#x), result %+v; want group 1 with Argument 0x123", v, g, a, result)
	}
}

// TestRefreshLeavesOtherLocalNATEntriesAlone checks that a PassThroughLocalNAT
// entry with no Argument, or for a prefix that is no class route, is never
// the sweep's: Galactic Worker writes those.
func TestRefreshLeavesOtherLocalNATEntriesAlone(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachableLocators(t, remote)
	tbl := NewEgressRouteTable(newFakeTable())
	putRaw(t, tbl, DefaultPrefix, localClassRoute(0))
	host := mustCIDR(t, "fd00:1::5/128")
	if err := tbl.RegisterPassThroughAs(1, host, PassThroughLocalNAT); err != nil {
		t.Fatal(err)
	}
	before := snapshotTable(tbl.table.(*fakeTable))
	if _, err := tbl.Refresh(nil, shardIPs(local, remote), WithLocalShards(nil)); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(before, snapshotTable(tbl.table.(*fakeTable))) {
		t.Error("the sweep changed a PassThroughLocalNAT entry it did not write")
	}
}

// TestRefreshWithoutRowsMatchesToday checks that the option with no row
// leaves a table exactly as a sweep without it does.
func TestRefreshWithoutRowsMatchesToday(t *testing.T) {
	local, remote, other := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachableLocators(t, remote, other)
	build := func() *EgressRouteTable {
		tbl := NewEgressRouteTable(newFakeTable())
		if err := tbl.Register(1, DefaultPrefix, tenantSID(other, 0x123)); err != nil {
			t.Fatal(err)
		}
		if err := tbl.RegisterGroup(2, nspNet(), 0, 0x456); err != nil {
			t.Fatal(err)
		}
		if err := tbl.RegisterPassThrough(1, mustCIDR(t, "fd00:1::/64")); err != nil {
			t.Fatal(err)
		}
		return tbl
	}
	plain, withOpt := build(), build()
	r1, err := plain.Refresh(nil, shardIPs(local, remote, other))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := withOpt.Refresh(nil, shardIPs(local, remote, other),
		WithLocalShards(map[uint32]LocalShard{9: {ShardSID: local}}))
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(snapshotTable(plain.table.(*fakeTable)), snapshotTable(withOpt.table.(*fakeTable))) {
		t.Error("a table with no row was swept differently with WithLocalShards")
	}
	if r1.Refreshed != r2.Refreshed || r1.Reselected != r2.Reselected || r1.Ungrouped != r2.Ungrouped {
		t.Errorf("results differ: %+v vs %+v", r1, r2)
	}
}
