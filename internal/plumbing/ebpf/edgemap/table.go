// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemap

import (
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Table is the minimal map-operation surface every table type in this
// package is written against, instead of directly against *ebpf.Map. Its
// method set matches *ebpf.Map's own Put/Lookup/Delete/Iterate closely
// enough that KernelTable (below) is a one-line adapter; this package's
// own tests substitute a fake, in-memory implementation to exercise
// register/unregister/reconcile logic without a kernel or root
// privileges -- see internal/plumbing/ebpf/usidmap's identical Table
// interface, which this one deliberately duplicates rather than imports
// (see doc.go).
type Table interface {
	// Put creates or overwrites the map entry at key with value.
	Put(key, value any) error

	// Lookup reads the map entry at key into valueOut. It returns
	// ebpf.ErrKeyNotExist (or, for a fake Table, an error satisfying
	// errors.Is(err, ebpf.ErrKeyNotExist)) if key is absent.
	Lookup(key, valueOut any) error

	// Delete removes the map entry at key. It returns ebpf.ErrKeyNotExist
	// (see Lookup) if key is already absent.
	Delete(key any) error

	// Iterate returns an Iterator walking every entry currently in the
	// map, in unspecified order -- matching *ebpf.Map.Iterate's own
	// documented behavior.
	Iterate() Iterator
}

// Iterator matches *ebpf.MapIterator's own Next/Err method set.
type Iterator interface {
	// Next decodes the next key/value pair into keyOut/valueOut and
	// reports whether one was available. Callers must check Err after
	// Next returns false to distinguish "iteration finished" from "an
	// error interrupted iteration."
	Next(keyOut, valueOut any) bool

	// Err returns the first error encountered during iteration, if any.
	Err() error
}

// KernelTable adapts a real, loaded *ebpf.Map -- e.g.
// edgeprog.EdgenatObjects.RuleTable, once loaded by
// internal/plumbing/ebpf/edgeattach -- to the Table interface every table
// type in this package is written against.
type KernelTable struct {
	Map *ebpf.Map
}

func (k KernelTable) Put(key, value any) error       { return k.Map.Put(key, value) }
func (k KernelTable) Lookup(key, valueOut any) error { return k.Map.Lookup(key, valueOut) }
func (k KernelTable) Delete(key any) error           { return k.Map.Delete(key) }
func (k KernelTable) Iterate() Iterator              { return k.Map.Iterate() }

// clockFn is a package-level override point so tests can control the
// generation values Register/Generation observe deterministically, instead
// of racing against a real, always-advancing clock. Production code always
// leaves this at its default, monotonicNow -- same CLOCK_MONOTONIC choice,
// for the same wall-clock-can-jump-backwards reason, as
// internal/plumbing/ebpf/usidmap/table.go's identical function.
var clockFn = monotonicNow

func monotonicNow() uint64 {
	var ts unix.Timespec
	// A clock_gettime failure is left to fail toward "never reaped" (0 >=
	// 0 in Reconcile's cutoff comparison) rather than toward misdelivery.
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
