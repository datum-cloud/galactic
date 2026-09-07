// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vrf

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockDir is the node-local parent directory for the lock serializing VRF table
// ID allocation across separate CNI invocations.
//
// Each ADD and DEL is its own process, so two pods attaching to different VPCs
// concurrently on one node make independent calls into this package against the
// same node-wide table ID space. An in-process mutex does nothing across those
// boundaries, and both processes then race in ID selection and link creation,
// surfacing as a busy-device error from the kernel.
const lockDir = "/var/lib/cni/galactic-vrf"

const lockFileName = "lock"

// fileLock is a cross-process advisory lock. Such locks are held per open file
// description, so any number of processes opening the same path contend for the
// same lock.
type fileLock struct {
	f *os.File
}

// acquireLock opens (creating if necessary) the well-known VRF lock file and
// blocks until an exclusive flock on it is acquired.
func acquireLock() (*fileLock, error) {
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return nil, fmt.Errorf("create VRF lock dir %q: %w", lockDir, err)
	}

	path := filepath.Join(lockDir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open VRF lock file %q: %w", path, err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock VRF lock file %q: %w", path, err)
	}

	return &fileLock{f: f}, nil
}

// close releases the flock and closes the underlying file.
func (l *fileLock) close() error {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return l.f.Close()
}
