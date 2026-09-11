// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import (
	"errors"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
)

func TestSumDropReason(t *testing.T) {
	reader := &fakeDropReasonsReader{
		perCPU: map[uint32][]uint64{
			nat66prog.DropReasonNat66NoReturnConn: {3, 0, 1, 2},
		},
	}

	got, err := SumDropReason(reader, nat66prog.DropReasonNat66NoReturnConn)
	if err != nil {
		t.Fatalf("SumDropReason() error = %v", err)
	}
	if got != 6 {
		t.Errorf("SumDropReason() = %d, want 6 (sum across every CPU)", got)
	}
}

func TestSumDropReason_AbsentIndexIsZero(t *testing.T) {
	reader := &fakeDropReasonsReader{perCPU: map[uint32][]uint64{}}

	got, err := SumDropReason(reader, nat66prog.DropReasonNat66PatExhausted)
	if err != nil {
		t.Fatalf("SumDropReason() error = %v", err)
	}
	if got != 0 {
		t.Errorf("SumDropReason() = %d, want 0 for an index with no counters yet", got)
	}
}

func TestSumDropReason_LookupError(t *testing.T) {
	wantErr := errors.New("simulated map lookup failure")
	reader := &fakeDropReasonsReader{err: wantErr}

	_, err := SumDropReason(reader, nat66prog.DropReasonNat66NoReturnConn)
	if err == nil {
		t.Fatal("SumDropReason() error = nil, want the wrapped lookup failure")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("SumDropReason() error = %v, want it to wrap %v", err, wantErr)
	}
}

func TestDropReasonTotals(t *testing.T) {
	reader := &fakeDropReasonsReader{
		perCPU: map[uint32][]uint64{
			nat66prog.DropReasonNat66NoReturnConn:     {1, 1},
			nat66prog.DropReasonNat66MalformedReturn:  {2, 2},
			nat66prog.DropReasonNat66PatExhausted:     {0, 0},
			nat66prog.DropReasonNat66MalformedForward: {3, 0},
			nat66prog.DropReasonNat66FibNoNeigh:       {0, 0},
			nat66prog.DropReasonNat66FibUnreachable:   {0, 0},
			nat66prog.DropReasonNat66FibFragNeeded:    {0, 0},
			nat66prog.DropReasonNat66FibLookupFailed:  {5, 0},
			nat66prog.DropReasonNat66AdjustHeadFailed: {0, 0},
		},
	}

	totals, err := DropReasonTotals(reader)
	if err != nil {
		t.Fatalf("DropReasonTotals() error = %v", err)
	}
	if len(totals) != int(nat66prog.DropReasonNat66Count) {
		t.Fatalf("DropReasonTotals() returned %d entries, want %d", len(totals), nat66prog.DropReasonNat66Count)
	}
	if totals[nat66prog.DropReasonNat66NoReturnConn] != 2 {
		t.Errorf("totals[no_return_conn] = %d, want 2", totals[nat66prog.DropReasonNat66NoReturnConn])
	}
	if totals[nat66prog.DropReasonNat66MalformedReturn] != 4 {
		t.Errorf("totals[malformed_return] = %d, want 4", totals[nat66prog.DropReasonNat66MalformedReturn])
	}
	if totals[nat66prog.DropReasonNat66FibLookupFailed] != 5 {
		t.Errorf("totals[fib_lookup_failed] = %d, want 5", totals[nat66prog.DropReasonNat66FibLookupFailed])
	}
}

func TestDropReasonTotals_LookupError(t *testing.T) {
	wantErr := errors.New("simulated map lookup failure")
	reader := &fakeDropReasonsReader{err: wantErr}

	_, err := DropReasonTotals(reader)
	if err == nil {
		t.Fatal("DropReasonTotals() error = nil, want the wrapped lookup failure")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("DropReasonTotals() error = %v, want it to wrap %v", err, wantErr)
	}
}
