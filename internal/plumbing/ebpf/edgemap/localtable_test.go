// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemap

import (
	"maps"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

func TestLocalTable_SetDeleteAndList(t *testing.T) {
	fake := newFakeMap[edgeprog.EdgedsrEdgeLocalKey, edgeprog.EdgedsrEdgeLocalValue]()
	lt := NewLocalTable(fake)
	a := netip.MustParseAddr("fc00:1:2:3:e1a5:7::")
	b := netip.MustParseAddr("fc00:1:2:3:e1a5:8::")

	if err := lt.SetLocalBackend(a, 42, 5); err != nil {
		t.Fatal(err)
	}
	if err := lt.SetLocalBackend(b, 0, 6); err != nil {
		t.Fatal(err)
	}
	got, err := lt.LocalBackends()
	if err != nil {
		t.Fatal(err)
	}
	if want := map[netip.Addr]uint32{a: 42, b: 0}; !maps.Equal(got, want) {
		t.Errorf("LocalBackends() = %v, want %v", got, want)
	}
	var raw edgeprog.EdgedsrEdgeLocalValue
	if err := fake.Lookup(edgeprog.EdgedsrEdgeLocalKey{Usid: a.As16()}, &raw); err != nil || raw.Generation != 5 {
		t.Errorf("row for %v = %+v, %v; want generation 5", a, raw, err)
	}

	if err := lt.DeleteLocalBackend(a); err != nil {
		t.Fatal(err)
	}
	if err := lt.DeleteLocalBackend(a); err != nil {
		t.Errorf("deleting an absent row: %v", err)
	}
	if got, _ := lt.LocalBackends(); len(got) != 1 {
		t.Errorf("after delete, LocalBackends() = %v, want only %v", got, b)
	}
}

func TestLocalTable_RejectsNonIPv6SIDs(t *testing.T) {
	lt := NewLocalTable(newFakeMap[edgeprog.EdgedsrEdgeLocalKey, edgeprog.EdgedsrEdgeLocalValue]())
	for _, sid := range []netip.Addr{{}, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.1")} {
		if err := lt.SetLocalBackend(sid, 1, 1); err == nil {
			t.Errorf("SetLocalBackend(%v) succeeded", sid)
		}
	}
}

func TestLocalTable_ReconcileKeepsLiveAndNewRows(t *testing.T) {
	lt := NewLocalTable(newFakeMap[edgeprog.EdgedsrEdgeLocalKey, edgeprog.EdgedsrEdgeLocalValue]())
	live := netip.MustParseAddr("fc00::1")
	stale := netip.MustParseAddr("fc00::2")
	fresh := netip.MustParseAddr("fc00::3")
	for sid, gen := range map[netip.Addr]uint64{live: 1, stale: 1, fresh: 10} {
		if err := lt.SetLocalBackend(sid, 7, gen); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := lt.Reconcile(map[netip.Addr]struct{}{live: {}}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != stale {
		t.Errorf("Reconcile removed %v, want only %v", removed, stale)
	}
	got, _ := lt.LocalBackends()
	if _, ok := got[fresh]; !ok {
		t.Errorf("a row written after the cutoff was removed: %v", got)
	}
}
