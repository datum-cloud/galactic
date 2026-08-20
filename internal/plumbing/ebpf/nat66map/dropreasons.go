// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import (
	"fmt"

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
)

// DropReasonsReader abstracts drop_reasons's per-CPU lookup (a
// BPF_MAP_TYPE_PERCPU_ARRAY keyed by drop reason index) down to the one
// operation this package needs, so tests can substitute an in-memory fake
// instead of a real, kernel-loaded map -- same interface shape as
// internal/plumbing/ebpf/edgemetrics.DropReasonsReader and
// internal/plumbing/ebpf/metrics's identical type. *ebpf.Map already
// satisfies this interface structurally.
type DropReasonsReader interface {
	Lookup(key, valueOut any) error
}

// SumDropReason reads drop_reasons[index] (one per-CPU counter slice) and
// returns the sum across every CPU -- the per-CPU-array summing idiom
// internal/plumbing/ebpf/prog's test helpers and
// internal/plumbing/ebpf/edgemetrics.Collector.collectDrops both already
// use, duplicated here rather than imported for the same "no shared
// datapath" reasoning doc.go gives for Table/KernelTable/Iterator.
func SumDropReason(reader DropReasonsReader, index uint32) (uint64, error) {
	var perCPU []uint64
	if err := reader.Lookup(index, &perCPU); err != nil {
		return 0, fmt.Errorf("nat66map: drop_reasons: lookup[%d]: %w", index, err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// DropReasonTotals reads every drop reason index
// (nat66prog.DropReasonNat66Count of them) and returns the per-CPU-summed
// total for each, keyed by its DropReasonNat66* index -- the shape a
// Prometheus collector (or any other caller) reads a full snapshot from in
// one call rather than looping SumDropReason itself.
func DropReasonTotals(reader DropReasonsReader) (map[uint32]uint64, error) {
	totals := make(map[uint32]uint64, nat66prog.DropReasonNat66Count)
	for i := range nat66prog.DropReasonNat66Count {
		total, err := SumDropReason(reader, i)
		if err != nil {
			return nil, fmt.Errorf("nat66map: drop_reasons: totals: %w", err)
		}
		totals[i] = total
	}
	return totals, nil
}
