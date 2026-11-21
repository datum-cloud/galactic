// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// withArgument is sid carrying a tenant Argument, as a VRF's class route does.
func withArgument(sid string, argument uint16) net.IP {
	b := netip.MustParseAddr(sid).As16()
	b[8] = b[8]&0xF0 | byte(argument>>8)&0x0F
	b[9] = byte(argument)
	return net.IP(b[:])
}

// TestSweepOrdered_LocalShardRows checks ordered mode with egress_local_shard:
// a table whose row names the first listed shard routes its class to this
// node's own shard, a table with no row is swept as before, and a route goes
// back to a shard SID once its row is removed.
func TestSweepOrdered_LocalShardRows(t *testing.T) {
	local, remote := shardSIDFor(0x10), shardSIDFor(0x11)
	build := func() *fixture {
		f := newFixture(t, testOrdered, []string{local, remote}, nil)
		for table, arg := range map[uint32]uint16{1: 0x123, 2: 0x456} {
			if err := f.routes.Register(table, egressroutemap.DefaultPrefix, withArgument(remote, arg)); err != nil {
				t.Fatal(err)
			}
		}
		return f
	}
	plain, f := build(), build()
	if err := plain.sweep(t); err != nil {
		t.Fatal(err)
	}
	f.g.localRows = map[uint32]egressroutemap.LocalShard{1: {ShardSID: netip.MustParseAddr(local), PairIfindex: 5}}
	f.g.localRowsKnown = true
	if err := f.sweep(t); err != nil {
		t.Fatal(err)
	}
	if row, ok, err := f.routes.LookupRow(1, egressroutemap.DefaultPrefix); err != nil || !ok || !row.PassThrough {
		t.Errorf("table 1 ::/0 = %+v (%t, %v), want a pass-through into the pair", row, ok, err)
	}
	want, _, _ := plain.routes.LookupRow(2, egressroutemap.DefaultPrefix)
	if got, _, _ := f.routes.LookupRow(2, egressroutemap.DefaultPrefix); got.PassThrough || !got.SID.Equal(want.SID) ||
		got.LinkIndex != want.LinkIndex {
		t.Errorf("table 2 (no row) ::/0 = %+v, want %+v as without rows", got, want)
	}

	f.g.localRows = map[uint32]egressroutemap.LocalShard{}
	if err := f.sweep(t); err != nil {
		t.Fatal(err)
	}
	if row, _, _ := f.routes.LookupRow(1, egressroutemap.DefaultPrefix); row.PassThrough || row.SID == nil {
		t.Errorf("table 1 ::/0 after the row went = %+v, want a shard SID again", row)
	}
}
