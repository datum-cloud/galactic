// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// fileLock is a cross-process advisory lock backed by flock(2). Each CNI ADD
// or DEL is a separate OS process, so in-process synchronization (a
// sync.Mutex or sync.Map) does nothing to serialize concurrent invocations
// against state shared across processes, such as a site-wide IPv4 pool.
// fileLock closes that gap: flock(2) locks are held per open file
// description, so any number of processes (or goroutines, each opening their
// own file description) opening the same path contend for the same lock.
type fileLock struct {
	f *os.File
}

// newFileLock opens (creating if necessary) the lock file at path and
// returns an unlocked fileLock.
func newFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %q: %w", path, err)
	}
	return &fileLock{f: f}, nil
}

// lock acquires an exclusive, blocking flock on the underlying file.
func (l *fileLock) lock() error {
	return unix.Flock(int(l.f.Fd()), unix.LOCK_EX)
}

// close releases the flock and closes the underlying file.
func (l *fileLock) close() error {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return l.f.Close()
}
