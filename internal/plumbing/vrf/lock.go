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

// lockDir is the well-known parent directory for the node-local flock that
// serializes VRF table ID allocation across separate CNI plugin invocations.
// Each CNI ADD/DEL is its own OS process, so two pods attaching to different
// VPCs concurrently on the same node construct independent calls into this
// package against the same node-wide VRF table ID space; an in-process
// sync.Mutex (vrfMu) does nothing to serialize across those process
// boundaries, which lets both processes race in findNextAvailableVRFID and
// netlink.LinkAdd, surfacing as "device or resource busy" from the kernel.
const lockDir = "/var/lib/cni/galactic-vrf"

const lockFileName = "lock"

// fileLock is a cross-process advisory lock backed by flock(2), mirroring
// internal/cni/ipam's fileLock: flock(2) locks are held per open file
// description, so any number of processes opening the same path contend for
// the same lock.
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
