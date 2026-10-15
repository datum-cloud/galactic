// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package tpmap

import (
	"errors"
	"fmt"
	"sort"
)

// ErrCountersExhausted is returned when no free block of rule counter rows is
// large enough. The caller keeps the last good snapshot and reports an
// installation failure; it never publishes a snapshot without its rows.
var ErrCountersExhausted = errors.New("tp_rule_counters has no free block large enough")

// CounterAllocator hands out contiguous blocks of tp_rule_counters rows, one
// per published snapshot, so a snapshot finds rule i's row at base+i.
//
// Free a snapshot's block only after the Publish that replaced it returned:
// the kernel has then waited for every program that could still be counting
// into it. A block is never freed on a timer or a reference count. Rows are
// not zeroed on Free; zero them with Maps.ZeroCounters before publishing a
// snapshot that uses them. A CounterAllocator is not safe for concurrent use.
type CounterAllocator struct {
	size uint32
	// used maps a block's base to its length.
	used map[uint32]uint32
}

// NewCounterAllocator manages rows [0, size).
func NewCounterAllocator(size uint32) *CounterAllocator {
	return &CounterAllocator{size: size, used: map[uint32]uint32{}}
}

// Allocate reserves n contiguous rows, first fit, and returns the first.
func (a *CounterAllocator) Allocate(n uint32) (uint32, error) {
	if n == 0 {
		n = 1 // every snapshot owns a block, even an empty one
	}
	var next uint32
	for _, base := range a.bases() {
		if base-next >= n {
			break
		}
		next = base + a.used[base]
	}
	if next+n > a.size {
		return 0, fmt.Errorf("%w: need %d rows", ErrCountersExhausted, n)
	}
	a.used[next] = n
	return next, nil
}

// Reserve marks [base, base+n) in use, for rebuilding the allocator from the
// snapshots a restarted agent finds still bound. It fails on an overlap.
func (a *CounterAllocator) Reserve(base, n uint32) error {
	n = max(n, 1)
	if base+n > a.size {
		return fmt.Errorf("rows [%d, %d) are outside tp_rule_counters", base, base+n)
	}
	for b, l := range a.used {
		if base < b+l && b < base+n {
			return fmt.Errorf("rows [%d, %d) overlap the block at %d", base, base+n, b)
		}
	}
	a.used[base] = n
	return nil
}

// Free releases the block at base.
func (a *CounterAllocator) Free(base uint32) {
	delete(a.used, base)
}

// InUse is the number of rows reserved.
func (a *CounterAllocator) InUse() uint32 {
	var n uint32
	for _, l := range a.used {
		n += l
	}
	return n
}

func (a *CounterAllocator) bases() []uint32 {
	out := make([]uint32, 0, len(a.used))
	for b := range a.used {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
