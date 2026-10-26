// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// KernelClock reports an error unless the kernel considers its clock
// synchronised, with an estimated error of at most MaxClockError. It reads
// the clock discipline with adjtimex without changing it, which needs no
// capability and which the default containerd and Docker seccomp profiles
// allow: a host whose time daemon (chrony, ntpd, systemd-timesyncd, Talos
// timed) disciplines the kernel clock passes, and one with no daemon
// reports TIME_ERROR. The kernel's maximum error is not used: it grows by
// 500 µs every second between the daemon's updates, which chrony spaces up
// to about 17 minutes apart, so it exceeds the bound on a healthy host; the
// kernel reports TIME_ERROR itself once it reaches 16 s.
func KernelClock() error {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return fmt.Errorf("read the clock discipline: %w", err)
	}
	if state == unix.TIME_ERROR {
		return errors.New("the kernel clock is not synchronised")
	}
	if estErr := time.Duration(tx.Esterror) * time.Microsecond; estErr > MaxClockError {
		return fmt.Errorf("the kernel clock's estimated error %s exceeds %s", estErr, MaxClockError)
	}
	return nil
}
