// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultWriterLock is the node's FRR writer lock, in the pod-scoped /run/frr
// every container that writes FRR shares.
const DefaultWriterLock = "/run/frr/fabric-agent.lock"

// FileLock is an exclusive flock on a file. Every process that changes the
// running FRR configuration or resets its sessions holds it while it does,
// so a reload never races a reset, a recovery or another reload.
type FileLock struct {
	Path string
	// Poll is how often a contended lock is retried. Zero selects 100ms.
	Poll time.Duration
}

// Lock blocks until it holds the lock or ctx ends.
func (l FileLock) Lock(ctx context.Context) (func(), error) {
	f, err := os.OpenFile(l.Path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open FRR writer lock: %w", err)
	}
	poll := l.Poll
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("lock FRR writer lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Locker serializes FRR writers.
type Locker interface {
	Lock(ctx context.Context) (unlock func(), err error)
}

// withLock runs fn holding l, or without a lock when l is nil.
func withLock(ctx context.Context, l Locker, fn func() error) error {
	if l == nil {
		return fn()
	}
	unlock, err := l.Lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}
