// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package tpmap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.datum.net/galactic/internal/captest"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/trafficpolicy"
)

// pinned pins f's traffic policy maps in a fresh bpffs directory and returns
// them opened from there, as galactic-router and the CNI plugins open them.
func (f *fixture) pinned(t *testing.T) (*Maps, string) {
	t.Helper()
	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-tpmap-test-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for name, mp := range map[string]interface{ Pin(string) error }{
		prog.UsidMapTpState:                f.objs.TpState,
		prog.UsidMapTpIfaceTable:           f.objs.TpIfaceTable,
		prog.UsidMapTpIfaceAddrTable:       f.objs.TpIfaceAddrTable,
		prog.UsidMapTpBindingTable:         f.objs.TpBindingTable,
		prog.UsidMapTpNatLocatorTable:      f.objs.TpNatLocatorTable,
		prog.UsidMapTpRuleCounters:         f.objs.TpRuleCounters,
		prog.UsidMapTpFallbackCounters:     f.objs.TpFallbackCounters,
		prog.UsidMapTpUnattributedCounters: f.objs.TpUnattributedCounters,
		prog.UsidMapTpAccountingErrors:     f.objs.TpAccountingErrors,
	} {
		if err := mp.Pin(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	m, err := OpenPinned(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, dir
}

func snapshotPins(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, snapshotPinDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func publishRules(t *testing.T, m *Maps, rules string, base uint32) {
	t.Helper()
	snap := Snapshot{Token: token, CounterBase: base, Generation: 3}
	entries, err := trafficpolicy.Compile(policy(t, rules))
	if err != nil {
		t.Fatal(err)
	}
	snap.Entries = entries
	if err := m.PublishSnapshot(ifindex, DirEgress, snap); err != nil {
		t.Fatal(err)
	}
}

// TestReadSnapshotWithoutSysAdmin: a process without CAP_SYS_ADMIN, such as
// galactic-router after a restart, lists and reads back every snapshot bound
// through pinned maps.
func TestReadSnapshotWithoutSysAdmin(t *testing.T) {
	f := newFixture(t, ModeAudit)
	f.iface(t)
	m, dir := f.pinned(t)
	publishRules(t, m, `[{"name":"a","action":"Allow"},{"name":"b","action":"Deny"}]`, 5)

	captest.WithoutSysAdmin(t, func() {
		restarted, err := OpenPinned(dir)
		if err != nil {
			t.Error(err)
			return
		}
		defer restarted.Close()
		keys, err := restarted.BoundKeys()
		if err != nil || len(keys) != 1 || keys[0].Ifindex != ifindex || keys[0].Direction != DirEgress {
			t.Errorf("BoundKeys = %v, %v; want ifindex %d egress", keys, err, ifindex)
		}
		snap, ok, err := restarted.ReadSnapshot(ifindex, DirEgress)
		if err != nil || !ok {
			t.Errorf("ReadSnapshot = %v, %v", ok, err)
			return
		}
		if snap.Token != token || snap.CounterBase != 5 || snap.Generation != 3 || len(snap.Entries) != 2 {
			t.Errorf("snapshot = %+v, want token %#x, base 5, generation 3, 2 entries", snap, token)
		}
		if _, ok, err := restarted.ReadSnapshot(ifindex, DirIngress); ok || err != nil {
			t.Errorf("unbound direction: ReadSnapshot = %v, %v; want none", ok, err)
		}
	})
}

// TestRepublishReplacesPin: each key keeps exactly one pin, the bound one.
func TestRepublishReplacesPin(t *testing.T) {
	f := newFixture(t, ModeAudit)
	f.iface(t)
	m, dir := f.pinned(t)
	publishRules(t, m, `[{"name":"a","action":"Allow"}]`, 0)
	publishRules(t, m, `[{"name":"a","action":"Allow"},{"name":"b","action":"Deny"}]`, 7)
	if pins := snapshotPins(t, dir); len(pins) != 1 || pins[0] != fmt.Sprintf("%d-%d", ifindex, DirEgress) {
		t.Fatalf("pins = %v, want one for ifindex %d egress", pins, ifindex)
	}
	captest.WithoutSysAdmin(t, func() {
		snap, ok, err := m.ReadSnapshot(ifindex, DirEgress)
		if err != nil || !ok || snap.CounterBase != 7 {
			t.Errorf("ReadSnapshot = %+v, %v, %v; want the second snapshot", snap, ok, err)
		}
	})
}

// TestUnbindingRemovesPin: Invalidate and RemoveInterface, which the CNI
// plugins call on DEL, leave no pin holding an unbound snapshot.
func TestUnbindingRemovesPin(t *testing.T) {
	f := newFixture(t, ModeAudit)
	f.iface(t)
	m, dir := f.pinned(t)
	publishRules(t, m, `[{"name":"a","action":"Allow"}]`, 0)
	if err := m.Invalidate(ifindex, DirEgress); err != nil {
		t.Fatal(err)
	}
	if pins := snapshotPins(t, dir); len(pins) != 0 {
		t.Errorf("after Invalidate: pins = %v, want none", pins)
	}
	publishRules(t, m, `[{"name":"a","action":"Allow"}]`, 0)
	if err := RemovePinnedInterface(dir, ifindex); err != nil {
		t.Fatal(err)
	}
	if pins := snapshotPins(t, dir); len(pins) != 0 {
		t.Errorf("after RemovePinnedInterface: pins = %v, want none", pins)
	}
}

// TestUnmatchedSnapshotIsUnreadable: a snapshot bound without a pin, or whose
// pin holds another map, is reported unreadable without CAP_SYS_ADMIN rather
// than read from the wrong map, and is still read by ID with it.
func TestUnmatchedSnapshotIsUnreadable(t *testing.T) {
	f := newFixture(t, ModeAudit)
	f.iface(t)
	m, dir := f.pinned(t)
	publishRules(t, m, `[{"name":"a","action":"Allow"}]`, 0)
	// f.maps has no pin directory, so this binding leaves the pin stale.
	publishRules(t, f.maps, `[{"name":"a","action":"Allow"},{"name":"b","action":"Deny"}]`, 9)
	if pins := snapshotPins(t, dir); len(pins) != 1 {
		t.Fatalf("pins = %v, want the stale one", pins)
	}
	unreadable := func() {
		captest.WithoutSysAdmin(t, func() {
			if _, err := m.BoundKeys(); err != nil {
				t.Errorf("BoundKeys: %v", err)
			}
			_, _, err := m.ReadSnapshot(ifindex, DirEgress)
			if !errors.Is(err, ErrSnapshotUnreadable) {
				t.Errorf("ReadSnapshot err = %v, want ErrSnapshotUnreadable", err)
			}
		})
	}
	unreadable()
	if snap, ok, err := m.ReadSnapshot(ifindex, DirEgress); err != nil || !ok || snap.CounterBase != 9 {
		t.Errorf("with CAP_SYS_ADMIN: ReadSnapshot = %+v, %v, %v; want the bound snapshot", snap, ok, err)
	}

	if err := os.Remove(filepath.Join(dir, snapshotPinDir, fmt.Sprintf("%d-%d", ifindex, DirEgress))); err != nil {
		t.Fatal(err)
	}
	unreadable()
}
