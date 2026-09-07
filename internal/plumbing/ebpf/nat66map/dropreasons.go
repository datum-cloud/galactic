// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import (
	"fmt"

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
)

// DropReasonsReader narrows the drop-reason map, a per-CPU array keyed by
// reason index, to the one operation this package needs, so tests can substitute
// an in-memory fake. A real loaded map already satisfies it structurally.
type DropReasonsReader interface {
	Lookup(key, valueOut any) error
}

// SumDropReason reads one drop-reason counter and returns the sum across every
// CPU. Duplicated here rather than imported, for the same no-shared-datapath
// reasoning the package doc comment gives for the map interfaces.
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

// DropReasonTotals reads every drop reason index and returns the per-CPU summed
// total for each, keyed by index: a full snapshot in one call rather than a
// caller looping over SumDropReason.
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
