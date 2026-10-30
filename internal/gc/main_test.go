// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"os"
	"testing"
)

// TestMain runs unprivileged tests without the node-wide VRF lock, whose
// directory only root can create. Root tests keep the real lock.
func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		vrfLockedFn = func(fn func() error) error { return fn() }
	}
	os.Exit(m.Run())
}
