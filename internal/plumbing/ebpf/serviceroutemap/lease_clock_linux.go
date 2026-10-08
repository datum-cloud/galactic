//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroutemap

import (
	"time"

	"golang.org/x/sys/unix"
)

func authorizationClock() (time.Time, uint64, error) {
	var clock unix.Timespec
	// Boottime includes suspension so a suspended node cannot extend a lease.
	// Sampling boottime before wall time errs toward shortening the lease.
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &clock); err != nil {
		return time.Time{}, 0, err
	}
	return time.Now(), uint64(clock.Nano()), nil
}
