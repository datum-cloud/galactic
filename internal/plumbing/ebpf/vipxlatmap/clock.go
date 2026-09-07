// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import "golang.org/x/sys/unix"

// monotonicNow returns a nanosecond reading from the monotonic clock, this
// table's in-memory generation source. See the package doc comment for why the
// generation is in-memory only here.
//
// A deliberate small duplicate of the uSID map layer's identical function, which
// is unexported in another package and so cannot be imported. Copying ten lines
// was judged simpler than exporting it for one cross-package use.
func monotonicNow() uint64 {
	var ts unix.Timespec
	// See the uSID map layer's equivalent for the failure mode if this call is
	// ever rejected: every reading in this process then reads 0, which fails
	// toward never reaping an entry rather than reaping one out from under live
	// state.
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
