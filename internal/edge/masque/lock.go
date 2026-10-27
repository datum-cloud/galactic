// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package masque

import (
	"context"
	"fmt"
)

// prepLock serializes the API work on one attachment or route. Unlike a
// sync.Mutex, a request waiting for it gives up when its context ends, so a
// request queued behind a slow preparation is bounded by its own deadline.
type prepLock chan struct{}

func newPrepLock() prepLock { return make(prepLock, 1) }

// lock waits for the lock until ctx ends.
func (p prepLock) lock(ctx context.Context) error {
	select {
	case p <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for another request's preparation: %w", context.Cause(ctx))
	}
}

// tryLock takes the lock when it is free.
func (p prepLock) tryLock() bool {
	select {
	case p <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p prepLock) unlock() { <-p }
