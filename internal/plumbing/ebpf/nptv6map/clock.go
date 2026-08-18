// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nptv6map

import "golang.org/x/sys/unix"

// monotonicNow returns a nanosecond CLOCK_MONOTONIC reading, used to stamp
// this process's own in-memory Generation bookkeeping (see doc.go and
// NPTv6Table.Register). This is a small, deliberate duplicate of
// usidmap's own unexported monotonicNow (internal/plumbing/ebpf/usidmap/
// table.go) rather than an exported/imported dependency on it: it is five
// lines wrapping one syscall, and usidmap's own egresskind.go/
// prog/dropreason.go already establish the precedent in this codebase of
// hand-keeping a tiny piece of logic in sync across packages rather than
// introducing a shared-but-barely-used export for it. See table.go's
// monotonicNow for the full reasoning on why CLOCK_MONOTONIC, not
// wall-clock time.Now(), is used here.
func monotonicNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
