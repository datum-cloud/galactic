// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"fmt"
	"os"
	"path/filepath"
)

// lockedState wraps the on-disk state directory and cross-process flock
// pattern shared by PoolAllocator (IPv6) and IPv4PoolAllocator: a directory
// holding a "lock" file plus one allocation marker file per allocated
// subnet/address, guarded by a flock so separate CNI plugin invocations
// (each ADD/DEL/CHECK is its own OS process) never race against each other
// over the same pool.
type lockedState struct {
	stateDir     string
	lockFileName string
}

// withLock acquires the pool's cross-process flock, runs fn, and releases
// the lock unconditionally before returning. Every read-modify-write against
// stateDir must go through this — in particular, a scan (to find which
// marker file, if any, belongs to a given containerID) and any removal that
// follows it must happen inside the *same* withLock call. Splitting them
// across two separate lock/unlock cycles, as an earlier version of
// findContainerMarker plus its callers did, leaves a window between the scan
// and the removal where a concurrent process sharing this pool can allocate
// or deallocate the very entry being acted on.
func (s lockedState) withLock(fn func() error) error {
	lock, err := newFileLock(filepath.Join(s.stateDir, s.lockFileName))
	if err != nil {
		return fmt.Errorf("open lock for %q: %w", s.stateDir, err)
	}
	defer func() { _ = lock.close() }()

	if err := lock.lock(); err != nil {
		return fmt.Errorf("lock %q: %w", s.stateDir, err)
	}
	return fn()
}

// entries reads stateDir and returns every marker filename except the lock
// file itself. Callers must already hold the flock (call from inside
// withLock).
func (s lockedState) entries() ([]os.DirEntry, error) {
	all, err := os.ReadDir(s.stateDir)
	if err != nil {
		return nil, fmt.Errorf("read pool state dir %q: %w", s.stateDir, err)
	}
	markers := make([]os.DirEntry, 0, len(all))
	for _, e := range all {
		if e.Name() == s.lockFileName {
			continue
		}
		markers = append(markers, e)
	}
	return markers, nil
}

// findContainerMarkerLocked scans stateDir for the marker file whose
// content matches containerID, returning its filename. Callers must already
// hold the flock (call from inside withLock).
func (s lockedState) findContainerMarkerLocked(containerID string) (string, bool) {
	entries, err := s.entries()
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		content, err := os.ReadFile(filepath.Join(s.stateDir, e.Name()))
		if err == nil && string(content) == containerID {
			return e.Name(), true
		}
	}
	return "", false
}
