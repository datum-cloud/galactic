// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nptv6map

import "golang.org/x/sys/unix"

// monotonicNow returns a nanosecond reading from the monotonic clock, stamping
// this process's in-memory generation bookkeeping.
//
// A deliberate small duplicate of the uSID map layer's unexported equivalent,
// rather than an exported dependency on it: it is a few lines wrapping one
// syscall. See that function for why the monotonic clock rather than a wall
// clock.
func monotonicNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
