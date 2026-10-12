// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// faultyTable wraps fakeTable with injected failures: iterErr ends every
// iteration with an error after its entries, and putFailAfter, when
// non-negative, fails every Put after that many have succeeded.
type faultyTable struct {
	*fakeTable
	iterErr      error
	putFailAfter int
	puts         int
}

func newFaultyTable() *faultyTable {
	return &faultyTable{fakeTable: newFakeTable(), putFailAfter: -1}
}

var errInjectedPut = errors.New("injected map write failure")

func (f *faultyTable) Put(key, value any) error {
	if f.putFailAfter >= 0 && f.puts >= f.putFailAfter {
		return errInjectedPut
	}
	f.puts++
	return f.fakeTable.Put(key, value)
}

func (f *faultyTable) Iterate() usidmap.Iterator {
	return &faultyIterator{Iterator: f.fakeTable.Iterate(), err: f.iterErr}
}

type faultyIterator struct {
	usidmap.Iterator
	err error
}

func (it *faultyIterator) Err() error { return it.err }

// tenantSID is shard's SID carrying argument.
func tenantSID(shard netip.Addr, argument uint16) net.IP {
	b := shard.As16()
	b[8] = b[8]&0xF0 | byte(argument>>8)&0x0F
	b[9] = byte(argument)
	return net.IP(b[:])
}

var nsp = netip.MustParsePrefix("2001:db8:64::/96")

func nspNet() *net.IPNet {
	return &net.IPNet{IP: net.IP(nsp.Addr().AsSlice()), Mask: net.CIDRMask(96, 128)}
}

// byClass is a WithShardGroups classifier: NAT66 to group 0, the NSP to 1.
func byClass(prefix *net.IPNet) (uint32, bool) {
	class, ok := ClassForRoute(prefix)
	switch {
	case !ok:
		return 0, false
	case class == NAT66Class:
		return 0, true
	case class == NAT64Class(nsp):
		return 1, true
	}
	return 0, false
}

// TestRefreshMovesShardEntriesOntoTheirClassGroups checks hashed mode's sweep:
// each shard-bound route becomes a sentinel for its class's group, keeping its
// Argument; a sentinel on the wrong group moves; and the sentinel count comes
// back per group.
func TestRefreshMovesShardEntriesOntoTheirClassGroups(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	shard := shardSID(0x10)
	if err := tbl.Register(1, DefaultPrefix, tenantSID(shard, 0x123)); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Register(1, nspNet(), tenantSID(shard, 0x123)); err != nil {
		t.Fatal(err)
	}
	if err := tbl.RegisterGroup(2, nspNet(), 3, 0x456); err != nil { // wrong group
		t.Fatal(err)
	}

	result, err := tbl.Refresh(nil, []net.IP{net.IP(shard.AsSlice())}, WithShardGroups(byClass))
	if err != nil {
		t.Fatal(err)
	}
	if result.Grouped != 3 || result.Refreshed != 3 || result.SentinelRoutes() != 3 ||
		result.GroupRoutes[0] != 1 || result.GroupRoutes[1] != 2 {
		t.Errorf("result = %+v, want 3 grouped, group 0 with 1 route and group 1 with 2", result)
	}
	for _, c := range []struct {
		table  uint32
		prefix *net.IPNet
		group  uint32
		arg    uint16
	}{{1, DefaultPrefix, 0, 0x123}, {1, nspNet(), 1, 0x123}, {2, nspNet(), 1, 0x456}} {
		key, _ := buildKey(c.table, c.prefix)
		value, _ := lookupRaw(tbl, key)
		if g, a := sentinelGroup(value); !isGroupSentinel(value) || g != c.group || a != c.arg {
			t.Errorf("table %d %s = group %d arg %#x, want group %d arg %#x", c.table, c.prefix, g, a, c.group, c.arg)
		}
	}
}

// TestRefreshLeavesAnUnservedClassAlone checks that a route whose class no
// group serves keeps its shard, and a sentinel for it stays counted.
func TestRefreshLeavesAnUnservedClassAlone(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	shard := shardSID(0x10)
	wkp := &net.IPNet{IP: net.IP(WellKnownPrefix.Addr().AsSlice()), Mask: net.CIDRMask(96, 128)}
	if err := tbl.Register(1, wkp, tenantSID(shard, 0x123)); err != nil {
		t.Fatal(err)
	}
	if err := tbl.RegisterGroup(2, wkp, 2, 0x456); err != nil {
		t.Fatal(err)
	}
	result, err := tbl.Refresh(nil, []net.IP{net.IP(shard.AsSlice())}, WithShardGroups(byClass))
	if err != nil {
		t.Fatal(err)
	}
	if result.Grouped != 0 || result.InGroup != 1 || result.GroupRoutes[2] != 1 {
		t.Errorf("result = %+v, want nothing grouped and the stray sentinel counted", result)
	}
}

// TestRefreshOrderedModeReturnsErrors covers F01 at its source: a sweep whose
// iteration or writes fail returns the error, so its caller cannot mistake a
// partial conversion for a complete one. A retry once the fault clears
// converts every sentinel.
func TestRefreshOrderedModeReturnsErrors(t *testing.T) {
	shard := shardSID(0x11)
	configured := []net.IP{net.IP(shard.AsSlice())}
	reachable(t, shard)
	// The resolver stub keys on the exact SID, so the tenant copies resolve too.
	prev := resolveLinkAndL2Fn
	resolveLinkAndL2Fn = func(sid net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		return 1, dpShardMAC, dpUplinkMAC, nil
	}
	t.Cleanup(func() { resolveLinkAndL2Fn = prev })

	setup := func() (*faultyTable, *EgressRouteTable) {
		raw := newFaultyTable()
		tbl := NewEgressRouteTable(raw)
		for table := uint32(1); table <= 4; table++ {
			if err := tbl.RegisterGroup(table, DefaultPrefix, 0, uint16(0x100+table)); err != nil { //nolint:gosec // test
				t.Fatal(err)
			}
		}
		return raw, tbl
	}
	sentinels := func(tbl *EgressRouteTable) int {
		n := 0
		for table := uint32(1); table <= 4; table++ {
			k, _ := buildKey(table, DefaultPrefix)
			v, _ := lookupRaw(tbl, k)
			if isGroupSentinel(v) {
				n++
			}
		}
		return n
	}

	t.Run("IterationError", func(t *testing.T) {
		raw, tbl := setup()
		raw.iterErr = errors.New("injected iteration failure")
		if _, err := tbl.Refresh(nil, configured); err == nil {
			t.Fatal("Refresh with a failing iterator = nil, want the error")
		}
		if n := sentinels(tbl); n != 4 {
			t.Errorf("%d sentinels after a failed iteration, want all 4 left untouched", n)
		}
	})
	t.Run("PartialWrite", func(t *testing.T) {
		raw, tbl := setup()
		raw.putFailAfter = raw.puts + 2
		result, err := tbl.Refresh(nil, configured)
		if !errors.Is(err, errInjectedPut) {
			t.Fatalf("Refresh with a failing write = %v, want the injected error", err)
		}
		if n := sentinels(tbl); n != 2 || result.Refreshed != 2 {
			t.Errorf("%d sentinels left and %d refreshed after the partial write, want 2 and 2", n, result.Refreshed)
		}

		raw.putFailAfter = -1
		result, err = tbl.Refresh(nil, configured)
		if err != nil || result.SentinelRoutes() != 0 || sentinels(tbl) != 0 {
			t.Errorf("retry = %+v, %v; want every sentinel converted and none counted", result, err)
		}
	})
	t.Run("Success", func(t *testing.T) {
		_, tbl := setup()
		result, err := tbl.Refresh(nil, configured)
		if err != nil || result.Ungrouped != 4 || result.SentinelRoutes() != 0 {
			t.Errorf("Refresh = %+v, %v; want 4 ungrouped and none left", result, err)
		}
		sid, _, _ := tbl.Lookup(2, DefaultPrefix)
		if !sid.Equal(tenantSID(shard, 0x102)) {
			t.Errorf("table 2's route = %s, want %s: the static shard with the sentinel's Argument",
				sid, tenantSID(shard, 0x102))
		}
	})
}

// TestRefreshCountsForeignSentinels checks that a sentinel in a table another
// namespace owns is left alone but still counted, so ordered mode never
// retires a group a foreign route still names.
func TestRefreshCountsForeignSentinels(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	if err := tbl.RegisterGroup(9, DefaultPrefix, 0, 0x10); err != nil {
		t.Fatal(err)
	}
	result, err := tbl.Refresh(map[uint32]struct{}{9: {}}, nil)
	if err != nil || result.SentinelRoutes() != 1 || result.Skipped != 1 {
		t.Errorf("Refresh = %+v, %v; want the foreign sentinel skipped and counted", result, err)
	}
}
