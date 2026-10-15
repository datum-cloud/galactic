// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package tpmap

import (
	"errors"
	"testing"
)

func TestCounterAllocator(t *testing.T) {
	a := NewCounterAllocator(10)
	first, err := a.Allocate(4)
	if err != nil || first != 0 {
		t.Fatalf("Allocate(4) = %d, %v; want 0", first, err)
	}
	second, err := a.Allocate(4)
	if err != nil || second != 4 {
		t.Fatalf("Allocate(4) = %d, %v; want 4", second, err)
	}
	if _, err := a.Allocate(3); !errors.Is(err, ErrCountersExhausted) {
		t.Fatalf("Allocate(3) with 2 free: err = %v, want ErrCountersExhausted", err)
	}
	a.Free(first)
	if got, err := a.Allocate(3); err != nil || got != 0 {
		t.Fatalf("Allocate(3) after freeing the first block = %d, %v; want 0", got, err)
	}
	if got, err := a.Allocate(0); err != nil || got != 3 {
		t.Errorf("Allocate(0) = %d, %v; want a one-row block at 3", got, err)
	}
	if n := a.InUse(); n != 8 {
		t.Errorf("InUse = %d, want 8", n)
	}
}

// TestCounterAllocatorReserve rebuilds the allocator a restarted agent
// derives from the snapshots it finds still bound.
func TestCounterAllocatorReserve(t *testing.T) {
	a := NewCounterAllocator(10)
	if err := a.Reserve(2, 3); err != nil {
		t.Fatal(err)
	}
	if err := a.Reserve(4, 2); err == nil {
		t.Error("overlapping Reserve succeeded")
	}
	if err := a.Reserve(9, 2); err == nil {
		t.Error("Reserve past the end succeeded")
	}
	if err := a.Reserve(3, 0); err == nil {
		t.Error("an empty Reserve inside a reserved block succeeded")
	}
	if got, err := a.Allocate(2); err != nil || got != 0 {
		t.Errorf("Allocate(2) = %d, %v; want the gap before the reserved block", got, err)
	}
	if got, err := a.Allocate(3); err != nil || got != 5 {
		t.Errorf("Allocate(3) = %d, %v; want 5", got, err)
	}
}
