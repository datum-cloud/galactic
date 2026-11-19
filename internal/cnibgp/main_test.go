// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.datum.net/galactic/internal/cni/vpcfence"
	"go.datum.net/galactic/internal/nodevpc"
)

// TestMain points the node-wide Argument lock and the VPC write fence at a
// temporary directory, so tests neither need root to create them nor contend
// with a real node's,
// and runs unprivileged tests without the VRF lock, whose directory only
// root can create.
func TestMain(m *testing.M) {
	os.Exit(func() int {
		dir, err := os.MkdirTemp("", "cnibgp-argument-lock-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer func() { _ = os.RemoveAll(dir) }()
		nodevpc.ArgumentLockDir = dir
		vpcfence.Dir = filepath.Join(dir, "ownership")
		if os.Geteuid() != 0 {
			vrfLockedFn = func(fn func() error) error { return fn() }
		}
		return m.Run()
	}())
}
