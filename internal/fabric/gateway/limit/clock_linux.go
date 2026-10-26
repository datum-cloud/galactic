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
// synchronised, with a maximum error of at most MaxClockError. It reads the
// clock discipline with adjtimex without changing it, which needs no
// capability: a host whose time daemon (chrony, ntpd, systemd-timesyncd,
// Talos timed) disciplines the kernel clock passes, and one with no daemon
// reports TIME_ERROR.
func KernelClock() error {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return fmt.Errorf("read the clock discipline: %w", err)
	}
	if state == unix.TIME_ERROR {
		return errors.New("the kernel clock is not synchronised")
	}
	if maxErr := time.Duration(tx.Maxerror) * time.Microsecond; maxErr > MaxClockError {
		return fmt.Errorf("the kernel clock's maximum error %s exceeds %s", maxErr, MaxClockError)
	}
	return nil
}
