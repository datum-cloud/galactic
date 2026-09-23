// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// answer is one stubbed resolveLinkAndL2 result.
type answer struct {
	link int
	dmac net.HardwareAddr
	smac net.HardwareAddr
	err  error
}

// resolverFor replaces resolveLinkAndL2Fn with one that answers per SID, so a
// test can move one entry's next hop and leave another's alone. A SID with no
// stubbed answer fails, which is what makes "this should never have been
// resolved at all" an assertable outcome.
func resolverFor(t *testing.T, answers map[string]answer) {
	t.Helper()
	prev := resolveLinkAndL2Fn
	resolveLinkAndL2Fn = func(sid net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		a, ok := answers[sid.String()]
		if !ok {
			return 0, nil, nil, errors.New("no answer stubbed for " + sid.String())
		}
		return a.link, a.dmac, a.smac, a.err
	}
	t.Cleanup(func() { resolveLinkAndL2Fn = prev })
}

// lookupRaw reads the whole stored value for key, unlike the exported Lookup,
// which returns only the SID -- these tests are about the resolved link and L2
// addresses stored beside it.
func lookupRaw(tbl *EgressRouteTable, key prog.UsidEgressRouteKey) (prog.UsidEgressRouteValue, error) {
	var value prog.UsidEgressRouteValue
	if err := tbl.table.Lookup(key, &value); err != nil {
		return prog.UsidEgressRouteValue{}, err
	}
	return value, nil
}

// TestRefreshRewritesAnEntryWhoseNextHopMoved is the regression test for #543:
// an egress route resolved before the fabric advertised its SID points out the
// management interface, and only a re-resolution moves it back onto the uplink.
func TestRefreshRewritesAnEntryWhoseNextHopMoved(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff02:9:e001::")

	// Written while the SID resolved out the wrong link, as a pre-convergence
	// CNI ADD would.
	if err := tbl.Register(1, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(::/0) = %v, want success", err)
	}

	const uplinkIndex = 1060
	uplinkDmac := net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x07, 0x6E, 0x0B}
	uplinkSmac := net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x46, 0x3D, 0x35}
	resolverFor(t, map[string]answer{
		sid.String(): {link: uplinkIndex, dmac: uplinkDmac, smac: uplinkSmac},
	})

	result, err := tbl.Refresh(nil, nil)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Refreshed != 1 {
		t.Errorf("Refresh() refreshed %d entries, want 1 (result: %+v)", result.Refreshed, result)
	}

	key, err := buildKey(1, DefaultPrefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	value, err := lookupRaw(tbl, key)
	if err != nil {
		t.Fatalf("lookupRaw: %v", err)
	}
	if value.LinkIfindex != uplinkIndex {
		t.Errorf("after Refresh, link_ifindex = %d, want %d", value.LinkIfindex, uplinkIndex)
	}
	if got := net.HardwareAddr(value.Dmac[:]).String(); got != uplinkDmac.String() {
		t.Errorf("after Refresh, dmac = %s, want %s", got, uplinkDmac)
	}
	if got := net.HardwareAddr(value.Smac[:]).String(); got != uplinkSmac.String() {
		t.Errorf("after Refresh, smac = %s, want %s", got, uplinkSmac)
	}
	if got := net.IP(value.Sid[:]); !got.Equal(sid) {
		t.Errorf("after Refresh, sid = %s, want it left alone at %s", got, sid)
	}
}

// TestRefreshLeavesAnUnresolvableEntryInPlace: a SID that does not resolve this
// time round is not evidence the route is wrong. Zeroing or dropping the entry
// would turn a stale next hop into no next hop at all.
func TestRefreshLeavesAnUnresolvableEntryInPlace(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff02:9:e001::")
	if err := tbl.Register(1, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(::/0) = %v, want success", err)
	}

	resolverFor(t, map[string]answer{
		sid.String(): {err: errors.New("no route over an SRv6 uplink")},
	})

	result, err := tbl.Refresh(nil, nil)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success even with an unresolvable entry", err)
	}
	if result.Unresolved != 1 || result.Refreshed != 0 {
		t.Errorf("Refresh() = %+v, want 1 unresolved and 0 refreshed", result)
	}

	key, err := buildKey(1, DefaultPrefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	value, err := lookupRaw(tbl, key)
	if err != nil {
		t.Fatalf("lookupRaw: %v", err)
	}
	if value.LinkIfindex != fakeLinkIndex {
		t.Errorf("link_ifindex = %d, want the original %d left untouched", value.LinkIfindex, fakeLinkIndex)
	}
	if got := net.IP(value.Sid[:]); !got.Equal(sid) {
		t.Errorf("sid = %s, want the original %s left untouched", got, sid)
	}
}

// TestRefreshSkipsPassThroughEntries: a pass-through carries no SID and is
// never encapsulated toward, so resolving one would fail on an all-zero address
// and count a phantom failure every sweep.
func TestRefreshSkipsPassThroughEntries(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	local := mustCIDR(t, "fd20:10:ff01::/96")
	if err := tbl.RegisterPassThrough(1, local); err != nil {
		t.Fatalf("RegisterPassThrough = %v, want success", err)
	}

	resolverFor(t, map[string]answer{}) // any resolution attempt fails

	result, err := tbl.Refresh(nil, nil)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Scanned != 1 {
		t.Errorf("Refresh() scanned %d, want 1", result.Scanned)
	}
	if result.Refreshed != 0 || result.Unresolved != 0 {
		t.Errorf("Refresh() = %+v, want a pass-through neither refreshed nor counted unresolved", result)
	}
}

// TestRefreshLeavesAnUnchangedEntryAlone keeps the sweep from rewriting every
// entry on a converged node twice a minute.
func TestRefreshLeavesAnUnchangedEntryAlone(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff02:9:e001::")
	if err := tbl.Register(1, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(::/0) = %v, want success", err)
	}

	// Same answer the entry was written with.
	resolverFor(t, map[string]answer{
		sid.String(): {link: fakeLinkIndex, dmac: fakeDmac, smac: fakeSmac},
	})

	result, err := tbl.Refresh(nil, nil)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Refreshed != 0 {
		t.Errorf("Refresh() refreshed %d entries, want 0 for an unchanged next hop", result.Refreshed)
	}
}

// Shard SIDs as the gvpc lab configures them: dfw's own, then sjc's, then
// iad's, with the placeholder Argument ADD overwrites. tenantSJC and tenantIAD
// are one tenant's copy of the two remote ones, carrying its VRFID 0x00a;
// dfw's own never resolves on dfw, so no test needs a copy of it.
var (
	shardDFW  = net.ParseIP("2001:db8:ff01:2001:e001::")
	shardSJC  = net.ParseIP("2001:db8:ff02:2001:e001::")
	shardIAD  = net.ParseIP("2001:db8:ff03:2001:e001::")
	shards    = []net.IP{shardDFW, shardSJC, shardIAD}
	tenantSJC = net.ParseIP("2001:db8:ff02:2001:e00a::")
	tenantIAD = net.ParseIP("2001:db8:ff03:2001:e00a::")
)

var (
	uplinkDmac = net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x07, 0x6E, 0x0B}
	uplinkSmac = net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x46, 0x3D, 0x35}
)

// registerOn writes tableID's ::/0 entry toward sid, resolved to link 1060.
func registerOn(t *testing.T, tbl *EgressRouteTable, tableID uint32, sid net.IP) {
	t.Helper()
	resolverFor(t, map[string]answer{sid.String(): {link: 1060, dmac: uplinkDmac, smac: uplinkSmac}})
	if err := tbl.Register(tableID, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(%d, ::/0, %s) = %v, want success", tableID, sid, err)
	}
}

// storedSID reads back table 1's ::/0 entry's SID.
func storedSID(t *testing.T, tbl *EgressRouteTable) net.IP {
	t.Helper()
	sid, ok, err := tbl.Lookup(1, DefaultPrefix)
	if err != nil || !ok {
		t.Fatalf("Lookup(1, ::/0) = (%v, %v, %v), want an entry", sid, ok, err)
	}
	return sid
}

// TestRefreshMovesAnEntryToAPreferredShardThatBecameReachable is the regression
// test for the gvpc lab's verify:nat-egress failure: iad's shard route reached
// dfw 300ms before sjc's, an ADD landed between the two and pinned the VRF to
// iad, and nothing ever moved it to sjc, ahead of iad in the configured order.
func TestRefreshMovesAnEntryToAPreferredShardThatBecameReachable(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	registerOn(t, tbl, 1, tenantIAD)

	// Both remote shards now resolve; dfw's own never does.
	resolverFor(t, map[string]answer{
		tenantSJC.String(): {link: 1061, dmac: uplinkDmac, smac: uplinkSmac},
		tenantIAD.String(): {link: 1060, dmac: uplinkDmac, smac: uplinkSmac},
	})

	result, err := tbl.Refresh(nil, shards)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Reselected != 1 || result.Refreshed != 1 {
		t.Errorf("Refresh() = %+v, want 1 reselected and 1 refreshed", result)
	}
	if got := storedSID(t, tbl); !got.Equal(tenantSJC) {
		t.Errorf("after Refresh, sid = %s, want sjc's shard with the tenant's Argument, %s", got, tenantSJC)
	}
	key, _ := buildKey(1, DefaultPrefix)
	if value, _ := lookupRaw(tbl, key); value.LinkIfindex != 1061 {
		t.Errorf("after Refresh, link_ifindex = %d, want sjc's next hop's 1061", value.LinkIfindex)
	}
}

// TestRefreshMovesAnEntryOffAShardThatStoppedResolving: a withdrawn shard route
// fails the entry over to the next shard in order, rather than leaving the VRF
// encapsulating toward a shard nobody can reach.
func TestRefreshMovesAnEntryOffAShardThatStoppedResolving(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	registerOn(t, tbl, 1, tenantSJC)

	resolverFor(t, map[string]answer{tenantIAD.String(): {link: 1060, dmac: uplinkDmac, smac: uplinkSmac}})

	result, err := tbl.Refresh(nil, shards)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Reselected != 1 {
		t.Errorf("Refresh() = %+v, want 1 reselected", result)
	}
	if got := storedSID(t, tbl); !got.Equal(tenantIAD) {
		t.Errorf("after Refresh, sid = %s, want iad's shard, %s", got, tenantIAD)
	}
}

// TestRefreshLeavesAnEntryOnTheFirstReachableShardAlone: an entry already on
// the shard the order picks, with an unchanged next hop, is not rewritten.
func TestRefreshLeavesAnEntryOnTheFirstReachableShardAlone(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	registerOn(t, tbl, 1, tenantSJC)

	resolverFor(t, map[string]answer{
		tenantSJC.String(): {link: 1060, dmac: uplinkDmac, smac: uplinkSmac},
		tenantIAD.String(): {link: 1060, dmac: uplinkDmac, smac: uplinkSmac},
	})

	result, err := tbl.Refresh(nil, shards)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Refreshed != 0 || result.Reselected != 0 {
		t.Errorf("Refresh() = %+v, want nothing rewritten", result)
	}
	if got := storedSID(t, tbl); !got.Equal(tenantSJC) {
		t.Errorf("after Refresh, sid = %s, want it left at %s", got, tenantSJC)
	}
}

// TestRefreshLeavesAShardEntryInPlaceWhenNoShardResolves: losing every route
// at once is a transient to ride out, like any other unresolved entry.
func TestRefreshLeavesAShardEntryInPlaceWhenNoShardResolves(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	registerOn(t, tbl, 1, tenantSJC)

	resolverFor(t, map[string]answer{})

	result, err := tbl.Refresh(nil, shards)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Unresolved != 1 || result.Refreshed != 0 {
		t.Errorf("Refresh() = %+v, want 1 unresolved and nothing rewritten", result)
	}
	if got := storedSID(t, tbl); !got.Equal(tenantSJC) {
		t.Errorf("after Refresh, sid = %s, want it left at %s", got, tenantSJC)
	}
}

// TestRefreshNeverReselectsANonShardEntry: an encapsulating entry toward some
// other SID -- here a remote node's delivery SID -- keeps it, even when a
// configured shard resolves.
func TestRefreshNeverReselectsANonShardEntry(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	delivery := net.ParseIP("2001:db8:ff02:1001:e00a::")
	prefix := mustCIDR(t, "fd20:10:ff02::/96")
	resolverFor(t, map[string]answer{delivery.String(): {link: 1060, dmac: uplinkDmac, smac: uplinkSmac}})
	if err := tbl.Register(1, prefix, delivery); err != nil {
		t.Fatalf("Register() = %v, want success", err)
	}

	resolverFor(t, map[string]answer{
		delivery.String():  {link: 1060, dmac: uplinkDmac, smac: uplinkSmac},
		tenantSJC.String(): {link: 1060, dmac: uplinkDmac, smac: uplinkSmac},
	})

	result, err := tbl.Refresh(nil, shards)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Reselected != 0 {
		t.Errorf("Refresh() = %+v, want nothing reselected", result)
	}
	if got, _, _ := tbl.Lookup(1, prefix); !got.Equal(delivery) {
		t.Errorf("after Refresh, sid = %s, want it left at %s", got, delivery)
	}
}

// TestRefreshResolvesEachShardOncePerSweep: every VRF's copy of a shard differs
// only in its Argument, so one unreachable shard must cost one resolution per
// sweep, not one per VRF.
func TestRefreshResolvesEachShardOncePerSweep(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	for tableID := uint32(1); tableID <= 5; tableID++ {
		sid := net.ParseIP(fmt.Sprintf("2001:db8:ff03:2001:e00%x::", tableID))
		registerOn(t, tbl, tableID, sid)
	}

	calls := map[uformat.LocatorKey]int{}
	prev := resolveLinkAndL2Fn
	resolveLinkAndL2Fn = func(sid net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		addr, _ := netip.AddrFromSlice(sid.To16())
		key, _ := uformat.LocatorKeyFromAddr(addr)
		calls[key]++
		if sid[5] == 0x03 { // iad's Block: the only shard that resolves
			return 1060, uplinkDmac, uplinkSmac, nil
		}
		return 0, nil, nil, errors.New("unreachable")
	}
	t.Cleanup(func() { resolveLinkAndL2Fn = prev })

	if _, err := tbl.Refresh(nil, shards); err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	for key, n := range calls {
		if n != 1 {
			t.Errorf("locator %#x resolved %d times across 5 VRFs, want once", uint64(key), n)
		}
	}
	if len(calls) != 3 {
		t.Errorf("resolved %d distinct shard locators, want all 3", len(calls))
	}
}
