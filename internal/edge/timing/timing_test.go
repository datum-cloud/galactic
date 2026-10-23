// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package timing

import (
	"testing"
	"time"
)

// TestParams pins the cell's contract: the values every participant must
// share, valid together, and the takeover interval they give.
func TestParams(t *testing.T) {
	if err := Params.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, want := Params.TakeoverWait().Round(10*time.Millisecond), 15530*time.Millisecond; got != want {
		t.Errorf("takeover interval %v, want %v", got, want)
	}
	if lease, renew := Params.Duration, RenewInterval; renew*3 > lease {
		t.Errorf("renewing every %v leaves fewer than two missed renewals in a %v lease", renew, lease)
	}
	if now, later := BootClock(), BootClock(); later < now {
		t.Errorf("CLOCK_BOOTTIME went back from %v to %v", now, later)
	}
}
