// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import "golang.org/x/sys/unix"

// monotonicNow returns a nanosecond reading from CLOCK_MONOTONIC, used as
// this table's in-memory Generation source (VipXlatTable.Generation) -- see
// the package doc comment for why this is in-memory only, unlike
// usidmap.VRFTable's kernel-stored generation field.
//
// This is a deliberate, small duplicate of
// internal/plumbing/ebpf/usidmap/table.go's own monotonicNow (identical
// body, identical reasoning: CLOCK_MONOTONIC rather than wall-clock
// time.Now(), for the same immune-to-NTP-step-corrections and
// stable-across-a-restart-within-the-same-boot properties that function's
// doc comment explains in full) -- that function is unexported inside a
// different package, so it cannot be imported directly; copying roughly ten
// lines here was judged simpler and clearer than exporting it solely for
// this one cross-package reuse.
func monotonicNow() uint64 {
	var ts unix.Timespec
	// See usidmap/table.go's monotonicNow for the failure-mode reasoning if
	// this syscall is ever rejected (e.g. a syscall-filtering sandbox):
	// every reading in this process then reads 0, which fails toward never
	// reaping an entry rather than reaping one out from under live state.
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
