// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ownership

import (
	"errors"
	"testing"
)

func anyOwner(Record) bool { return true }

// TestTakeoverFencesAndAdoptsInOneStep moves a scope to a new owner with no
// transitioning window: tickets issued before it are stale, the new ticket
// requires a snapshot, and an Exclusive writer is never refused.
func TestTakeoverFencesAndAdoptsInOneStep(t *testing.T) {
	a, old := owned(t)
	tk, err := a.Takeover(scope, WorkerOwnerPrefix+"n:2", anyOwner)
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Resync {
		t.Fatal("takeover ticket does not require a snapshot")
	}
	rec, err := a.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Transitioning || !rec.Pending || rec.Owner != WorkerOwnerPrefix+"n:2" {
		t.Fatalf("record after takeover = %+v", rec)
	}
	if _, err := a.Commit(old, mustNotRun(t)); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("commit by the replaced owner = %v, want ErrNotOwner", err)
	}
	if err := a.Exclusive(scope, noCheck, func() error { return nil }); err != nil {
		t.Fatalf("exclusive write after takeover = %v", err)
	}
	// The exclusive write staled the takeover ticket; a fresh one commits
	// only as a snapshot.
	if _, err := a.CommitSnapshot(tk, mustNotRun(t)); !errors.Is(err, ErrStale) {
		t.Fatalf("snapshot from a ticket issued before an exclusive write = %v, want ErrStale", err)
	}
	next, err := a.Begin(scope, WorkerOwnerPrefix+"n:2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Commit(next, mustNotRun(t)); !errors.Is(err, ErrResyncRequired) {
		t.Fatalf("incremental commit before the snapshot = %v, want ErrResyncRequired", err)
	}
	if _, err := a.CommitSnapshot(next, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// TestTakeoverRefusedLeavesRecord changes nothing when from refuses the
// current owner.
func TestTakeoverRefusedLeavesRecord(t *testing.T) {
	a, tk := owned(t)
	before, err := a.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Takeover(scope, WorkerOwnerPrefix+"n:2", func(r Record) bool { return WorkerOwned(r.Owner) })
	if !errors.Is(err, ErrNotOwner) {
		t.Fatalf("takeover of another writer's scope = %v, want ErrNotOwner", err)
	}
	if after, _ := a.Read(scope); after != before {
		t.Fatalf("record changed: %+v, was %+v", after, before)
	}
	if _, err := a.Commit(tk, func() error { return nil }); err != nil {
		t.Fatalf("owner's ticket after a refused takeover = %v", err)
	}
}

// TestTakeoverCompletesAnOpenFence ends a transfer an earlier Fence left
// open, as when a process died between Fence and Adopt.
func TestTakeoverCompletesAnOpenFence(t *testing.T) {
	a, _ := owned(t)
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Exclusive(scope, noCheck, mustNotRun(t)); !errors.Is(err, ErrTransitioning) {
		t.Fatalf("exclusive write during the open fence = %v, want ErrTransitioning", err)
	}
	tk, err := a.Takeover(scope, WorkerOwnerPrefix+"n:3", anyOwner)
	if err != nil {
		t.Fatal(err)
	}
	if tk.Generation <= gen {
		t.Fatalf("takeover generation %d, want above the fence's %d", tk.Generation, gen)
	}
	if _, err := a.Adopt(scope, "late", gen); !errors.Is(err, ErrStale) {
		t.Fatalf("adopt of the superseded fence = %v, want ErrStale", err)
	}
	if err := a.Exclusive(scope, noCheck, func() error { return nil }); err != nil {
		t.Fatalf("exclusive write after takeover = %v", err)
	}
}

// TestExclusiveIfSeesTheRecord refuses a write by the owner it reads under
// the lock, leaving the record unchanged.
func TestExclusiveIfSeesTheRecord(t *testing.T) {
	a, _ := owned(t)
	errOwned := errors.New("owned")
	before, _ := a.Read(scope)
	err := a.ExclusiveIf(scope, func(r Record) error {
		if r.Owner == "cni" {
			return errOwned
		}
		return nil
	}, mustNotRun(t))
	if !errors.Is(err, errOwned) {
		t.Fatalf("ExclusiveIf = %v, want the check's error", err)
	}
	if after, _ := a.Read(scope); after != before {
		t.Fatalf("record changed: %+v, was %+v", after, before)
	}
}

func TestWorkerOwned(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner string
		want  bool
	}{
		{"Worker", WorkerOwnerPrefix + "node:abc", true},
		{"Edge", "galactic-edge:node:abc", false},
		{"Unowned", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := WorkerOwned(tc.owner); got != tc.want {
				t.Fatalf("WorkerOwned(%q) = %t, want %t", tc.owner, got, tc.want)
			}
		})
	}
}
