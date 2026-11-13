// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemap

import (
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// TestVIPTable_ReturnStatsFollowListeners covers #1377's bookkeeping:
// ListReturnStats reports each listener of a claimed address, a zero row for
// one that has sourced nothing, and Unregister removes only that listener's
// return row until the address's last listener goes, which takes the port-0
// row with it.
func TestVIPTable_ReturnStatsFollowListeners(t *testing.T) {
	returnStats := newFakeReturnStatsTable()
	vt := NewVIPTable(newFakeTable(), newFakeStatsTable(), newFakeAddrTable(), returnStats)

	https := testKey(t)
	dns := VIPKey{Proto: 17, VPort: 53, VIP: https.VIP}
	for _, key := range []VIPKey{https, dns} {
		if err := vt.Register(key, edgeprog.AffinityNone,
			[]Backend{testBackend(t)}, [MaglevTableSize]byte{}); err != nil {
			t.Fatalf("Register(%+v): %v", key, err)
		}
	}
	httpsWire, err := toWireKey(https)
	if err != nil {
		t.Fatalf("toWireKey: %v", err)
	}
	unmatched := edgeprog.EdgedsrVipKey{Proto: 58, Vip: httpsWire.Vip}
	returnStats.entries[httpsWire] = edgeprog.EdgedsrVipStatsValue{Packets: 9}
	returnStats.entries[unmatched] = edgeprog.EdgedsrVipStatsValue{Packets: 2}

	listed := func() map[VIPKey]uint64 {
		t.Helper()
		entries, err := vt.ListReturnStats()
		if err != nil {
			t.Fatalf("ListReturnStats: %v", err)
		}
		out := make(map[VIPKey]uint64, len(entries))
		for _, e := range entries {
			if _, dup := out[e.VIPKey]; dup {
				t.Errorf("ListReturnStats reported %+v twice", e.VIPKey)
			}
			out[e.VIPKey] = e.Packets
		}
		return out
	}

	got := listed()
	want := map[VIPKey]uint64{https: 9, dns: 0, {Proto: 58, VIP: https.VIP}: 2}
	if len(got) != len(want) {
		t.Errorf("ListReturnStats = %v, want %v", got, want)
	}
	for k, v := range want {
		if p, ok := got[k]; !ok || p != v {
			t.Errorf("ListReturnStats[%+v] = %d (present %v), want %d", k, p, ok, v)
		}
	}

	if err := vt.Unregister(https); err != nil {
		t.Fatalf("Unregister(https): %v", err)
	}
	if _, ok := returnStats.entries[httpsWire]; ok {
		t.Errorf("Unregister kept the removed listener's return row")
	}
	if _, ok := returnStats.entries[unmatched]; !ok {
		t.Errorf("Unregister of one listener removed the address's port-0 row")
	}

	if err := vt.Unregister(dns); err != nil {
		t.Fatalf("Unregister(dns): %v", err)
	}
	if len(returnStats.entries) != 0 {
		t.Errorf("vip_return_stats_table holds %v after the last listener went, want none", returnStats.entries)
	}
	if got := listed(); len(got) != 0 {
		t.Errorf("ListReturnStats = %v after the last listener went, want none", got)
	}
}
