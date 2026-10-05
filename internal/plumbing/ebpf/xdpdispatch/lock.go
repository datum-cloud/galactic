// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpdispatch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// lockRetryInterval is how often Lock tries again while another process holds
// the lock.
const lockRetryInterval = 100 * time.Millisecond

// Lock takes the node-wide dispatch lock, an flock on the pin directory, and
// returns the function that releases it. It waits while another process holds
// it, until ctx is done.
//
// Hold it across EnsureLink and, when EnsureLink bounced the interface, the
// wait for a bond member to rejoin. A process may hold it once: a second
// call from the same process blocks until the first is released.
func (d *Dispatcher) Lock(ctx context.Context) (func(), error) {
	return lockDir(ctx, d.dir)
}

// lockDir locks dir, waiting until ctx is done.
func lockDir(ctx context.Context, dir string) (func(), error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("xdpdispatch: open %q for locking: %w", dir, err)
	}
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(fd, unix.LOCK_UN)
				_ = unix.Close(fd)
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("xdpdispatch: lock %q: %w", dir, err)
		}
		select {
		case <-ctx.Done():
			_ = unix.Close(fd)
			return nil, fmt.Errorf("xdpdispatch: waiting for the dispatch lock on %q: %w", dir, ctx.Err())
		case <-time.After(lockRetryInterval):
		}
	}
}

// Lease renews slot's lease every LeaseRenewal until ctx is done, starting
// now. It leaves the lease in place when it stops, so a restart within
// LeaseTTL never lets the slot lapse. A failed renewal is reported to onError,
// which may be nil.
func (d *Dispatcher) Lease(ctx context.Context, slot Slot, onError func(error)) {
	renew := func() {
		if err := d.Renew(slot); err != nil && onError != nil {
			onError(err)
		}
	}
	renew()
	ticker := time.NewTicker(LeaseRenewal)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renew()
		}
	}
}
