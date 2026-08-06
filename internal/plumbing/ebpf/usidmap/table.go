// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Table is the minimal map-operation surface every table type in this
// package (VRFTable, LocatorTable, FunctionTable) is written against,
// instead of directly against *ebpf.Map. Its method set matches *ebpf.Map's
// own Put/Lookup/Delete/Iterate closely enough that KernelTable (below) is
// a one-line adapter; usidmap_test.go substitutes a fake, in-memory
// implementation to exercise register/unregister/reconcile logic without a
// kernel or root privileges (Milestone 3.3's own exit criterion: "unit
// tests against a mocked map interface").
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
// prog.UsidObjects.VrfTable, LocatorTable, or FunctionTable, once loaded
// and pinned by internal/plumbing/ebpf/attach.Load -- to the Table
// interface every table type in this package is written against.
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
// leaves this at its default, monotonicNow.
var clockFn = monotonicNow

// monotonicNow returns a nanosecond reading from CLOCK_MONOTONIC, used as
// the generation value stamped into vrf_table (and locator_table) entries
// at write time (see doc.go's "plugin-binary-vs-run-container race"
// section).
//
// CLOCK_MONOTONIC, not wall-clock time.Now(), deliberately: a wall-clock
// reading can jump backwards (NTP step correction), which would let a
// freshly Registered entry's generation compare as *older* than a cutoff
// captured moments before in real chronological order -- exactly the
// scenario this mechanism exists to prevent misjudging as stale. Go's
// time.Now() does carry an internal monotonic reading, but it is only ever
// comparable between two time.Time values from the same process and is not
// exposed as a raw, storable integer -- unsuitable for a value that must be
// written into a map entry and compared later, possibly by a different
// process (design plan §5.4's two-actor split). unix.CLOCK_MONOTONIC gives
// a raw, storable nanosecond count directly, immune to wall-clock jumps,
// and -- critically -- stable across a control-daemon restart within the
// same boot (it is not reset by a process restart, only by a reboot, and a
// reboot also destroys every pinned bpffs map this generation value would
// otherwise need to outlive, so that reset is harmless).
func monotonicNow() uint64 {
	var ts unix.Timespec
	// CLOCK_MONOTONIC is a well-known, always-valid clock id on Linux; the
	// only realistic failure mode is a syscall-filtering sandbox rejecting
	// clock_gettime entirely, in which case ts stays zeroed and every call
	// in this process -- both Register's generation stamp and Generation's
	// own cutoff snapshot -- reads 0. Reconcile's "keep if Generation >=
	// cutoff" check then becomes 0 >= 0, which is true: entries are kept,
	// never reaped, for as long as the rejection persists. This fails
	// toward a leak (stale entries pile up, requiring a later restart or
	// manual cleanup once clock_gettime works again), not toward
	// misdelivery -- an entry never gets reaped out from under live
	// traffic just because this syscall is unavailable.
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
