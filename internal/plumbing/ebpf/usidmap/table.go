// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Table is the minimal map-operation surface every table type in this package is
// written against, rather than a loaded map directly. Its method set is close
// enough to the real map's that KernelTable is a one-line adapter, and tests
// substitute an in-memory fake to exercise register, unregister, and reconcile
// logic without a kernel or root.
type Table interface {
	// Put creates or overwrites the map entry at key with value.
	Put(key, value any) error

	// Lookup reads the entry at key into valueOut, returning an error matching
	// ebpf.ErrKeyNotExist when key is absent.
	Lookup(key, valueOut any) error

	// Delete removes the map entry at key. It returns ebpf.ErrKeyNotExist
	// (see Lookup) if key is already absent.
	Delete(key any) error

	// Iterate returns an Iterator over every entry currently in the map, in
	// unspecified order.
	Iterate() Iterator
}

// Iterator matches *ebpf.MapIterator's own Next/Err method set.
type Iterator interface {
	// Next decodes the next pair into keyOut and valueOut and reports whether
	// one was available. Callers must check Err after it returns false, to tell
	// a finished iteration from an interrupted one.
	Next(keyOut, valueOut any) bool

	// Err returns the first error encountered during iteration, if any.
	Err() error
}

// KernelTable adapts a real, loaded map to the Table interface every table type
// in this package is written against.
type KernelTable struct {
	Map *ebpf.Map
}

func (k KernelTable) Put(key, value any) error       { return k.Map.Put(key, value) }
func (k KernelTable) Lookup(key, valueOut any) error { return k.Map.Lookup(key, valueOut) }
func (k KernelTable) Delete(key any) error           { return k.Map.Delete(key) }
func (k KernelTable) Iterate() Iterator              { return k.Map.Iterate() }

// clockFn is an override point so tests can control the generation values
// deterministically instead of racing a real, always-advancing clock.
var clockFn = monotonicNow

// monotonicNow returns a nanosecond reading from the monotonic clock, used as
// the generation stamped into map entries at write time.
//
// Monotonic rather than wall clock, deliberately: a wall-clock reading can jump
// backwards under a time correction, which would let a freshly registered entry
// compare as older than a cutoff captured moments earlier, exactly the
// misjudgement this mechanism exists to prevent. Go's own time values do carry
// an internal monotonic reading, but it is comparable only between two values
// from the same process and is not exposed as a storable integer, which this
// must be: it is written into a map entry and compared later, possibly by
// another process.
//
// The raw clock is also stable across a control-daemon restart within one boot.
// It resets only on reboot, which also destroys every pinned map the value
// would otherwise need to outlive.
func monotonicNow() uint64 {
	var ts unix.Timespec
	// The monotonic clock is always valid on Linux; the only realistic failure
	// is a syscall-filtering sandbox rejecting the call, in which case every
	// reading in this process is 0. Reconcile's "keep at or above cutoff" check
	// then compares 0 against 0, which holds, so entries are kept and never
	// reaped while the rejection persists. That fails toward a leak, cleaned up
	// by a later restart, rather than toward reaping an entry out from under
	// live traffic.
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
