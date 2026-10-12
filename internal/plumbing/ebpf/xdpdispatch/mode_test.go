// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"

	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
)

func openDispatcherInMode(t *testing.T, dir string, mode xdpmode.Mode) *Dispatcher {
	t.Helper()
	d, err := Open(context.Background(), dir, mode)
	if err != nil {
		t.Fatalf("Open(%s): %v", mode, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// kernelMode returns the mode the kernel reports ifindex's XDP hook in.
func kernelMode(t *testing.T, ifindex int) xdpmode.Mode {
	t.Helper()
	mode, ok, err := attachedMode(ifindex)
	if err != nil {
		t.Fatalf("read attach mode of ifindex %d: %v", ifindex, err)
	}
	if !ok {
		t.Fatalf("ifindex %d holds no XDP program in a known mode", ifindex)
	}
	return mode
}

// coveredNATSlot fills the NAT slot on ifindex through d and returns a check
// of that slot's coverage through any dispatcher, so a test can watch the slot
// survive a migration.
func coveredNATSlot(t *testing.T, d *Dispatcher, ifindex int) func(*Dispatcher) error {
	t.Helper()
	nat := stubProgram(t, xdpDrop)
	if err := locked(t, d).SetRole(ifindex, RoleEgress); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := locked(t, d).Fill(SlotNAT, nat); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	return func(through *Dispatcher) error { return through.Coverage(ifindex, SlotNAT, nat) }
}

func TestEnsureLink_AttachesInTheDispatchersMode(t *testing.T) {
	for _, mode := range []xdpmode.Mode{xdpmode.Native, xdpmode.Generic} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := testPinDir(t)
			ifindex := testVeth(t, "xdpm")
			d := openDispatcherInMode(t, dir, mode)

			bounced, err := locked(t, d).EnsureLink(ifindex)
			if err != nil || !bounced {
				t.Fatalf("EnsureLink = %v, %v; want an attach", bounced, err)
			}
			if got := kernelMode(t, ifindex); got != mode {
				t.Errorf("kernel reports %s mode, want %s", got, mode)
			}
			if linked, err := d.Linked(ifindex); err != nil || !linked {
				t.Errorf("Linked = %v, %v; want true", linked, err)
			}
			if bounced, err := locked(t, d).EnsureLink(ifindex); err != nil || bounced {
				t.Errorf("second EnsureLink = %v, %v; want no change", bounced, err)
			}
		})
	}
}

// TestEnsureLink_MigratesALinkToTheSelectedMode is the upgrade from native to
// generic mode on a node whose dispatcher already runs: the pinned link is
// moved, and the root, the slot, its lease and the role row come through
// untouched, so the datapath is covered again the moment the new link is up.
func TestEnsureLink_MigratesALinkToTheSelectedMode(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpn")
	native := openDispatcherInMode(t, dir, xdpmode.Native)
	ensureLink(t, native, ifindex)
	covered := coveredNATSlot(t, native, ifindex)
	if err := covered(native); err != nil {
		t.Fatalf("before migration: Coverage = %v", err)
	}
	rootBefore, err := native.RootID()
	if err != nil {
		t.Fatal(err)
	}

	generic := openDispatcherInMode(t, dir, xdpmode.Generic)
	if linked, err := generic.Linked(ifindex); err != nil || linked {
		t.Errorf("native link under a generic dispatcher: Linked = %v, %v; want false", linked, err)
	}
	if pinned, err := generic.Pinned(ifindex); err != nil || !pinned {
		t.Errorf("Pinned = %v, %v; want true in either mode", pinned, err)
	}
	if err := generic.Coverage(ifindex, SlotNAT, nil); !errors.Is(err, ErrModeMismatch) {
		t.Errorf("native link under a generic dispatcher: Coverage = %v, want ErrModeMismatch", err)
	}

	bounced, err := locked(t, generic).EnsureLink(ifindex)
	if err != nil || !bounced {
		t.Fatalf("migrating EnsureLink = %v, %v; want a bounce", bounced, err)
	}
	if got := kernelMode(t, ifindex); got != xdpmode.Generic {
		t.Fatalf("after migration the kernel reports %s mode, want generic", got)
	}
	if linked, err := generic.Linked(ifindex); err != nil || !linked {
		t.Errorf("after migration: Linked = %v, %v; want true", linked, err)
	}
	rootAfter, err := generic.RootID()
	if err != nil {
		t.Fatal(err)
	}
	if rootAfter != rootBefore {
		t.Errorf("root changed across the migration: %d, then %d", rootBefore, rootAfter)
	}
	if got := attachedProgID(t, ifindex); got != uint32(rootAfter) {
		t.Errorf("ifindex runs program %d after migration, want the root %d", got, rootAfter)
	}
	roles, err := generic.Roles(ifindex)
	if err != nil || roles&RoleEgress == 0 {
		t.Errorf("roles after migration = %b, %v; want the egress role kept", roles, err)
	}
	if err := covered(generic); err != nil {
		t.Errorf("after migration: Coverage = %v, want the slot covered again", err)
	}
	if err := native.Coverage(ifindex, SlotNAT, nil); !errors.Is(err, ErrModeMismatch) {
		t.Errorf("a native dispatcher's Coverage after migration = %v, want ErrModeMismatch", err)
	}
}

// TestEnsureLink_FailedMigrationRestoresThePreviousMode covers a migration
// whose new attach fails: the root goes back on in the mode it was in, the
// error is returned, and the link still reports the mismatch so the next
// reconcile retries.
func TestEnsureLink_FailedMigrationRestoresThePreviousMode(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpr")
	native := openDispatcherInMode(t, dir, xdpmode.Native)
	ensureLink(t, native, ifindex)
	covered := coveredNATSlot(t, native, ifindex)

	orig := attachXDPFn
	t.Cleanup(func() { attachXDPFn = orig })
	attachXDPFn = func(opts link.XDPOptions) (link.Link, error) {
		if opts.Flags == link.XDPGenericMode {
			return nil, errors.New("injected generic attach failure")
		}
		return orig(opts)
	}

	generic := openDispatcherInMode(t, dir, xdpmode.Generic)
	_, err := locked(t, generic).EnsureLink(ifindex)
	if err == nil {
		t.Fatal("EnsureLink with a failing generic attach: want an error")
	}
	if msg := err.Error(); !strings.Contains(msg, "injected generic attach failure") ||
		!strings.Contains(msg, "restored native") {
		t.Errorf("error = %v, want the attach failure and the restored mode", err)
	}
	if got := kernelMode(t, ifindex); got != xdpmode.Native {
		t.Errorf("after a failed migration the kernel reports %s mode, want native restored", got)
	}
	if pinned, err := generic.Pinned(ifindex); err != nil || !pinned {
		t.Errorf("after a failed migration: Pinned = %v, %v; want the restored link pinned", pinned, err)
	}
	if err := generic.Coverage(ifindex, SlotNAT, nil); !errors.Is(err, ErrModeMismatch) {
		t.Errorf("after a failed migration: Coverage = %v, want ErrModeMismatch so it is retried", err)
	}
	if err := covered(native); err != nil {
		t.Errorf("after a failed migration the native dispatcher's slot is uncovered: %v", err)
	}

	attachXDPFn = orig
	if _, err := locked(t, generic).EnsureLink(ifindex); err == nil || !strings.Contains(err.Error(), "retrying after") {
		t.Errorf("immediate retry = %v, want it held back by the backoff", err)
	}
	if got := kernelMode(t, ifindex); got != xdpmode.Native {
		t.Errorf("a backed-off retry touched the link: kernel reports %s mode", got)
	}

	now := time.Now()
	origNow := wallNowFn
	t.Cleanup(func() { wallNowFn = origNow })
	wallNowFn = func() time.Time { return now.Add(migrationBackoffMin + time.Second) }
	if bounced, err := locked(t, generic).EnsureLink(ifindex); err != nil || !bounced {
		t.Fatalf("retried migration = %v, %v; want a bounce", bounced, err)
	}
	if got := kernelMode(t, ifindex); got != xdpmode.Generic {
		t.Errorf("after the retry the kernel reports %s mode, want generic", got)
	}
	if err := covered(generic); err != nil {
		t.Errorf("after the retry: Coverage = %v, want covered", err)
	}
}

// TestEnsureLink_LeavesAForeignGenericProgramAlone: the foreign-program guard
// holds in generic mode too.
func TestEnsureLink_LeavesAForeignGenericProgramAlone(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdpg")
	foreign := stubProgram(t, xdpPass)
	fl, err := link.AttachXDP(link.XDPOptions{Program: foreign, Interface: ifindex, Flags: link.XDPGenericMode})
	if err != nil {
		t.Fatalf("attach foreign program: %v", err)
	}
	t.Cleanup(func() { _ = fl.Close() })
	foreignInfo, _ := foreign.Info()
	foreignID, _ := foreignInfo.ID()

	for _, mode := range []xdpmode.Mode{xdpmode.Generic, xdpmode.Native} {
		d := openDispatcherInMode(t, dir, mode)
		if _, err := locked(t, d).EnsureLink(ifindex); !errors.Is(err, ErrForeignProgram) {
			t.Errorf("%s dispatcher over a foreign generic program: err = %v, want ErrForeignProgram", mode, err)
		}
		if got := attachedProgID(t, ifindex); got != uint32(foreignID) {
			t.Errorf("%s dispatcher replaced the foreign program: ifindex runs %d, want %d", mode, got, foreignID)
		}
	}
}

// TestEnsureLink_LeavesTheLinkToANewerHostMode covers two processes that
// selected different modes, as after a NIC appeared between their starts: the
// one opened first sees the newer record, refuses to move the link back, and
// says it needs a restart.
func TestEnsureLink_LeavesTheLinkToANewerHostMode(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdph")
	generic := openDispatcherInMode(t, dir, xdpmode.Generic)
	ensureLink(t, generic, ifindex)

	// A process started later selects native mode and records it.
	native := openDispatcherInMode(t, dir, xdpmode.Native)
	ensureLink(t, native, ifindex)
	if got := kernelMode(t, ifindex); got != xdpmode.Native {
		t.Fatalf("the newer process did not move the link: kernel reports %s mode", got)
	}

	if _, err := locked(t, generic).EnsureLink(ifindex); !errors.Is(err, ErrHostModeChanged) {
		t.Errorf("stale process EnsureLink = %v, want ErrHostModeChanged", err)
	}
	if got := kernelMode(t, ifindex); got != xdpmode.Native {
		t.Errorf("the stale process moved the link back: kernel reports %s mode", got)
	}
}

func TestBackoff_DoublesUpToTheCap(t *testing.T) {
	d := &Dispatcher{backoff: map[int]migrationRetry{}}
	now := time.Unix(1000, 0)
	origNow := wallNowFn
	t.Cleanup(func() { wallNowFn = origNow })
	wallNowFn = func() time.Time { return now }

	want := migrationBackoffMin
	for range 10 {
		d.recordMigration(7, errors.New("attach failed"))
		if got := d.backoff[7].delay; got != want {
			t.Fatalf("delay = %s, want %s", got, want)
		}
		want = min(2*want, migrationBackoffMax)
	}
	d.recordMigration(7, nil)
	if _, ok := d.backoff[7]; ok {
		t.Error("a successful migration kept its backoff")
	}
}

// TestOpenForSlots_LeavesTheHostModeAlone covers a datapath turned off on a
// generic host: clearing its slots must not record a mode, or every running
// datapath would stop migrating links, and it can never attach.
func TestOpenForSlots_LeavesTheHostModeAlone(t *testing.T) {
	dir := testPinDir(t)
	ifindex := testVeth(t, "xdps")
	generic := openDispatcherInMode(t, dir, xdpmode.Generic)

	slots, err := OpenForSlots(context.Background(), dir)
	if err != nil {
		t.Fatalf("OpenForSlots: %v", err)
	}
	t.Cleanup(func() { _ = slots.Close() })
	if err := locked(t, slots).Clear(SlotNAT); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := locked(t, slots).EnsureLink(ifindex); err == nil {
		t.Error("EnsureLink on a slots-only dispatcher: want an error")
	}

	recorded, ok, err := generic.recordedHostMode()
	if err != nil || !ok || recorded != xdpmode.Generic {
		t.Errorf("host mode after OpenForSlots = %s, %v, %v; want generic", recorded, ok, err)
	}
	ensureLink(t, generic, ifindex)
	if got := kernelMode(t, ifindex); got != xdpmode.Generic {
		t.Errorf("kernel reports %s mode, want generic", got)
	}
}
