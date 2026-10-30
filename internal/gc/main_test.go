// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"os"
	"testing"

	"go.datum.net/galactic/internal/plumbing/vrf"
)

// TestMain runs unprivileged tests without the node-wide VRF lock, whose
// directory only root can create. Root tests keep the real lock.
//
// No test reads the node's real VRF table reservations: a sweep finding the
// test machine's reservations could release them. A test exercising
// reservations substitutes its own.
func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		vrfLockedFn = func(fn func() error) error { return fn() }
	}
	vrfReservationsFn = func() ([]vrf.Reservation, error) { return nil, nil }
	vrfReleaseFn = func(string, uint32) error { return nil }
	os.Exit(m.Run())
}
