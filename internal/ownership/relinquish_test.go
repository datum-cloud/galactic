// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ownership

import (
	"errors"
	"testing"
)

func ownedBy(owner string) func(Record) bool {
	return func(r Record) bool { return r.Owner == owner }
}

// TestRelinquishLeavesScopeUnowned gives a scope up with no next owner: the
// previous owner's tickets are stale, an Exclusive writer is never refused,
// and the next owner claims it and must commit a snapshot first.
func TestRelinquishLeavesScopeUnowned(t *testing.T) {
	a, old := owned(t)
	gen, err := a.Relinquish(scope, ownedBy("cni"), "")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := a.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Owner != "" || rec.Transitioning || !rec.Pending || rec.Generation != gen || gen != old.Generation+1 {
		t.Fatalf("record after relinquish = %+v, generation %d", rec, gen)
	}
	if _, err := a.Commit(old, mustNotRun(t)); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("commit by the previous owner = %v, want ErrNotOwner", err)
	}
	if _, err := a.Begin(scope, "cni"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("begin by the previous owner = %v, want ErrNotOwner", err)
	}
	if err := a.Exclusive(scope, noCheck, func() error { return nil }); err != nil {
		t.Fatalf("exclusive write after relinquish = %v", err)
	}
	tk, err := a.Claim(scope, WorkerOwnerPrefix+"n:1")
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Resync {
		t.Fatal("claim of a relinquished scope does not require a snapshot")
	}
	if _, err := a.Commit(tk, mustNotRun(t)); !errors.Is(err, ErrResyncRequired) {
		t.Fatalf("incremental commit after relinquish = %v, want ErrResyncRequired", err)
	}
	if _, err := a.CommitSnapshot(tk, func() error { return nil }); err != nil {
		t.Fatalf("snapshot commit after relinquish = %v", err)
	}
}

// TestRelinquishToHandbackLabel gives a scope up to a neutral label: no
// writer claims it, and a legacy writer takes it over by accepting the label.
func TestRelinquishToHandbackLabel(t *testing.T) {
	a, _ := owned(t)
	worker := WorkerOwnerPrefix + "n:1"
	tk, err := a.Takeover(scope, worker, anyOwner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CommitSnapshot(tk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	label := HandbackOwnerPrefix + "1700000000"
	if _, err := a.Relinquish(scope, func(r Record) bool { return WorkerOwned(r.Owner) }, label); err != nil {
		t.Fatal(err)
	}
	if !HandedBack(label) || HandedBack(worker) {
		t.Fatal("HandedBack does not recognize the handback label alone")
	}
	if _, err := a.Claim(scope, "galactic-edge/n/2"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("claim of a handed-back scope = %v, want ErrNotOwner", err)
	}
	tk, err = a.Takeover(scope, "galactic-edge/n/2", func(r Record) bool { return HandedBack(r.Owner) })
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Resync {
		t.Fatal("takeover of a handed-back scope does not require a snapshot")
	}
	if _, err := a.CommitSnapshot(tk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// TestRelinquishRefusedChangesNothing leaves a scope whose owner from refuses
// exactly as it was, so a stale process cannot give up its successor's scope.
func TestRelinquishRefusedChangesNothing(t *testing.T) {
	a, tk := owned(t)
	before, err := a.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Relinquish(scope, ownedBy("someone-else"), ""); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("refused relinquish = %v, want ErrNotOwner", err)
	}
	after, err := a.Read(scope)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("record changed from %+v to %+v", before, after)
	}
	if _, err := a.Commit(tk, func() error { return nil }); err != nil {
		t.Fatalf("owner's commit after a refused relinquish = %v", err)
	}
}

// TestRelinquishCompletesOpenTransfer gives up a scope an earlier Fence left
// transitioning, so a dead handover never leaves it refusing writers.
func TestRelinquishCompletesOpenTransfer(t *testing.T) {
	a, _ := owned(t)
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Relinquish(scope, anyOwner, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Adopt(scope, "late", gen); !errors.Is(err, ErrStale) {
		t.Fatalf("adopt of the fenced transfer after relinquish = %v, want ErrStale", err)
	}
	if err := a.Exclusive(scope, noCheck, func() error { return nil }); err != nil {
		t.Fatalf("exclusive write after relinquish = %v", err)
	}
}

// TestPeekReadsWithoutLock checks that Peek returns the record a commit
// wrote, and an empty one for a scope with none, while another holder keeps
// the scope locked.
func TestPeekReadsWithoutLock(t *testing.T) {
	a, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tk, err := a.Claim("vpc-1", "w")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan Record, 1)
	if _, err := a.CommitSnapshot(tk, func() error {
		// The scope's lock is held here; Peek must not wait for it.
		r, err := a.Peek("vpc-1")
		if err != nil {
			return err
		}
		done <- r
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.Owner != "w" {
		t.Fatalf("Peek under the lock = %+v", r)
	}
	if r, err := a.Peek("vpc-2"); err != nil || r.Owner != "" {
		t.Fatalf("Peek of an unrecorded scope = %+v, %v", r, err)
	}
	if _, err := a.Peek("../x"); err == nil {
		t.Fatal("Peek accepted an invalid scope name")
	}
}
