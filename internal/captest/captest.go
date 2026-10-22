// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package captest runs test code with fewer capabilities than the root test
// process has, to check that code works under a container's narrower set.
//
// It is a regular importable package rather than a test file, since one
// package's test files cannot import another's.
package captest

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// WithoutSysAdmin runs fn on an OS thread whose effective capabilities lack
// CAP_SYS_ADMIN, as galactic-router's container does, and waits for it.
// Capabilities are per thread, so fn must make its system calls from its own
// goroutine: a goroutine fn starts runs on other threads, with the full set.
// Since fn does not run on the test goroutine, it reports failures with
// t.Error rather than t.Fatal. The thread exits with fn, so the
// rest of the test keeps the full set.
func WithoutSysAdmin(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Never unlocked: the runtime destroys a locked thread when its
		// goroutine exits, so no other goroutine inherits the reduced set.
		runtime.LockOSThread()
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		if err := unix.Capget(&hdr, &data[0]); err != nil {
			t.Errorf("capget: %v", err)
			return
		}
		data[unix.CAP_SYS_ADMIN/32].Effective &^= 1 << (unix.CAP_SYS_ADMIN % 32)
		if err := unix.Capset(&hdr, &data[0]); err != nil {
			t.Errorf("drop CAP_SYS_ADMIN: %v", err)
			return
		}
		fn()
	}()
	<-done
}
