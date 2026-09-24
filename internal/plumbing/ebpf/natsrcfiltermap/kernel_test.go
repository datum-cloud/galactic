// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natsrcfiltermap

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF) to load BPF maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// TestKernelFilterRoundTrip drives every Filter operation against the real
// maps, which the fake cannot vouch for: LPM key encoding, trie iteration, and
// per-CPU reads.
func TestKernelFilterRoundTrip(t *testing.T) {
	requireRoot(t)

	var objs natprog.NatObjects
	if err := natprog.LoadNatObjects(&objs, nil); err != nil {
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	f := NewKernelFilter(&objs)

	if err := f.PutAllow(netip.MustParsePrefix("fc00:3:4::/48"), Binding{Slots: 0b11}); err != nil {
		t.Fatalf("PutAllow: %v", err)
	}
	if err := f.PutAllow(netip.MustParsePrefix("fc00:3:5:1::/64"), Binding{AnyInterface: true}); err != nil {
		t.Fatalf("PutAllow: %v", err)
	}
	if err := f.DeleteAllow(netip.MustParsePrefix("fc00:9::/48")); err != nil {
		t.Fatalf("DeleteAllow(absent): %v", err)
	}
	entries, err := f.ListAllow()
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	wantEntries := []AllowEntry{
		{Prefix: netip.MustParsePrefix("fc00:3:4::/48"), Binding: Binding{Slots: 0b11}},
		{Prefix: netip.MustParsePrefix("fc00:3:5:1::/64"), Binding: Binding{AnyInterface: true}},
	}
	if !reflect.DeepEqual(entries, wantEntries) {
		t.Errorf("ListAllow = %+v, want %+v", entries, wantEntries)
	}

	if err := f.SyncUplinkSlots(map[uint32]uint8{2: 0, 5: 1}); err != nil {
		t.Fatalf("SyncUplinkSlots: %v", err)
	}
	if err := f.SyncUplinkSlots(map[uint32]uint8{5: 0}); err != nil {
		t.Fatalf("SyncUplinkSlots: %v", err)
	}
	slots, err := f.UplinkSlots()
	if err != nil {
		t.Fatalf("UplinkSlots: %v", err)
	}
	if want := map[uint32]uint8{5: 0}; !reflect.DeepEqual(slots, want) {
		t.Errorf("UplinkSlots = %v, want %v", slots, want)
	}

	if err := f.SetMode(ModeAudit); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	if err := f.MarkPopulated(3); err != nil {
		t.Fatalf("MarkPopulated: %v", err)
	}
	cfg, err := f.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if want := (Config{Mode: ModeAudit, Populated: true, Generation: 3}); cfg != want {
		t.Errorf("Config = %+v, want %+v", cfg, want)
	}

	stats, err := f.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats != (Stats{}) {
		t.Errorf("Stats on a fresh map = %+v, want zero", stats)
	}
	denied, err := f.Denied()
	if err != nil {
		t.Fatalf("Denied: %v", err)
	}
	if len(denied) != 0 {
		t.Errorf("Denied on a fresh map = %+v, want none", denied)
	}
}
