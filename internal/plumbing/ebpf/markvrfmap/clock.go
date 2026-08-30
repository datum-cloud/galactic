// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package markvrfmap

import "golang.org/x/sys/unix"

// monotonicNow returns a nanosecond CLOCK_MONOTONIC reading, used to stamp
// this process's own in-memory Generation bookkeeping (see doc.go). A
// deliberate small duplicate of usidmap's and ifindexvrfmap's own copies of
// the same -- see ifindexvrfmap/clock.go's doc comment for why duplicating
// this five-line syscall wrapper, rather than exporting it from usidmap, is
// the intentional choice here.
func monotonicNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
