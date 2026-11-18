// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vpcfence

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.datum.net/galactic/internal/ownership"
)

const vpc = "00000000e1"

func authority(t *testing.T) *ownership.Authority {
	t.Helper()
	Dir = t.TempDir()
	a, err := ownership.New(Dir)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestWriteStalesOwnerTickets runs a write on a scope another process owns,
// without waiting for that owner, and leaves the owner's earlier ticket stale.
func TestWriteStalesOwnerTickets(t *testing.T) {
	a := authority(t)
	tk, err := a.Claim(ownership.VPCScope(vpc), ownership.WorkerOwnerPrefix+"n:1")
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := Write(context.Background(), vpc, func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("Write = %v (ran %t), want it run", err, ran)
	}
	if _, err := a.CommitSnapshot(tk, func() error { return nil }); !errors.Is(err, ownership.ErrStale) {
		t.Fatalf("owner commit from a ticket issued before the write = %v, want ErrStale", err)
	}
}

// TestWriteWaitsForAnOpenTransfer retries while ownership moves and writes
// once the transfer completes.
func TestWriteWaitsForAnOpenTransfer(t *testing.T) {
	a := authority(t)
	scope := ownership.VPCScope(vpc)
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Write(context.Background(), vpc, func() error { return nil }) }()
	select {
	case err := <-done:
		t.Fatalf("Write returned %v during the transfer", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := a.Adopt(scope, ownership.WorkerOwnerPrefix+"n:1", gen); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Write after the transfer = %v", err)
	}
}

// TestWriteGivesUpWithItsContext returns ErrTransitioning once ctx ends.
func TestWriteGivesUpWithItsContext(t *testing.T) {
	a := authority(t)
	if _, err := a.Fence(ownership.VPCScope(vpc)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := Write(ctx, vpc, func() error {
		t.Error("write ran during the transfer")
		return nil
	})
	if !errors.Is(err, ownership.ErrTransitioning) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Write = %v, want ErrTransitioning and the deadline", err)
	}
}

// TestWriteUnlessWorker runs nothing on a scope a Worker owns and writes one
// no Worker owns.
func TestWriteUnlessWorker(t *testing.T) {
	a := authority(t)
	if _, err := a.Claim(ownership.VPCScope(vpc), ownership.WorkerOwnerPrefix+"n:1"); err != nil {
		t.Fatal(err)
	}
	err := WriteUnlessWorker(context.Background(), vpc, func() error {
		t.Error("write ran on a Worker-owned scope")
		return nil
	})
	if !errors.Is(err, ownership.ErrWorkerOwned) {
		t.Fatalf("WriteUnlessWorker = %v, want ErrWorkerOwned", err)
	}
	ran := false
	if err := WriteUnlessWorker(context.Background(), "e2", func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("WriteUnlessWorker on an unowned scope = %v (ran %t)", err, ran)
	}
}
