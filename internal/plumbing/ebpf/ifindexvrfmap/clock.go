// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import "golang.org/x/sys/unix"

// monotonicNow returns a nanosecond reading from the monotonic clock, stamping
// this process's in-memory generation bookkeeping. A deliberate small duplicate
// of the equivalent in the sibling map packages, for the reason given there:
// it is a few lines wrapping one syscall.
func monotonicNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
