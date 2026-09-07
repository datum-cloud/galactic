// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"fmt"
	"os"
	"path/filepath"
)

// lockedState wraps the on-disk state directory and cross-process lock both
// allocators share: a directory holding a lock file plus one marker file per
// allocation, guarded so separate plugin invocations, each its own process,
// never race over the same pool.
type lockedState struct {
	stateDir     string
	lockFileName string
}

// withLock acquires the pool's cross-process lock, runs fn, and releases the
// lock unconditionally before returning.
//
// Every read-modify-write against the state directory must go through it. In
// particular a scan, to find which marker belongs to a container, and any
// removal that follows must happen inside the same call: splitting them across
// two lock cycles leaves a window where a concurrent process sharing the pool
// can allocate or release the very entry being acted on.
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

// entries reads the state directory and returns every marker filename except the
// lock file. Callers must already hold the lock.
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

// findContainerMarkerLocked scans the state directory for the marker whose
// content matches containerID and returns its filename. Callers must already
// hold the lock.
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
