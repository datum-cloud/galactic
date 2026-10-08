// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
)

// dedupKey identifies one operation of one request on this node.
type dedupKey struct {
	requestID string
	node      string
	operation fabricv1.QueryType
}

// dedupEntry is one in-flight or completed execution.
type dedupEntry struct {
	// args fingerprints the canonical arguments; reusing a key with other
	// arguments is refused.
	args    string
	expires time.Time
	done    chan struct{}
	// resp and err are set before done is closed.
	resp  *fabricv1.ExecuteResponse
	err   error
	bytes int
	// seq orders completed entries for eviction.
	seq uint64
}

// dedupCache coalesces concurrent duplicates and keeps completed results
// until their request expires, within fixed entry and byte ceilings. Eviction
// removes expired entries first, then the oldest completed ones; in-flight
// entries are never evicted. An evicted or restarted cache can let a repeat
// run again, which execution and packet budgets still bound.
type dedupCache struct {
	mu         sync.Mutex
	entries    map[dedupKey]*dedupEntry
	maxEntries int
	maxBytes   int
	bytes      int
	seq        uint64
	now        func() time.Time

	// hits counts requests answered from the cache or an in-flight
	// duplicate.
	hits func()
}

func newDedupCache(maxEntries, maxBytes int, now func() time.Time) *dedupCache {
	return &dedupCache{entries: make(map[dedupKey]*dedupEntry), maxEntries: maxEntries, maxBytes: maxBytes, now: now}
}

// do runs fn once per key while the entry lives. A caller arriving while fn
// runs waits for its result; one arriving after gets the stored result.
func (c *dedupCache) do(ctx context.Context, key dedupKey, args string, expires time.Time,
	fn func() (*fabricv1.ExecuteResponse, error)) (*fabricv1.ExecuteResponse, error) {
	c.mu.Lock()
	c.sweepLocked()
	if e, ok := c.entries[key]; ok {
		c.mu.Unlock()
		if e.args != args {
			return nil, errcode.Status(errcode.DuplicateConflict,
				"request "+key.requestID+" was already used with different arguments")
		}
		if c.hits != nil {
			c.hits()
		}
		select {
		case <-e.done:
			return e.resp, e.err
		case <-ctx.Done():
			return nil, errcode.FromError(ctx.Err())
		}
	}
	e := &dedupEntry{args: args, expires: expires, done: make(chan struct{})}
	c.entries[key] = e
	c.mu.Unlock()

	resp, err := fn()

	c.mu.Lock()
	e.resp, e.err = resp, err
	if resp != nil {
		e.bytes = proto.Size(resp)
	}
	c.seq++
	e.seq = c.seq
	c.bytes += e.bytes
	close(e.done)
	c.evictLocked()
	c.mu.Unlock()
	return resp, err
}

// sweepLocked drops completed entries whose request has expired.
func (c *dedupCache) sweepLocked() {
	now := c.now()
	for k, e := range c.entries {
		if now.After(e.expires) && completed(e) {
			c.removeLocked(k, e)
		}
	}
}

// evictLocked enforces the ceilings by dropping the oldest completed
// entries.
func (c *dedupCache) evictLocked() {
	c.sweepLocked()
	for len(c.entries) > c.maxEntries || c.bytes > c.maxBytes {
		var oldestKey dedupKey
		var oldest *dedupEntry
		for k, e := range c.entries {
			if completed(e) && (oldest == nil || e.seq < oldest.seq) {
				oldestKey, oldest = k, e
			}
		}
		if oldest == nil {
			return
		}
		c.removeLocked(oldestKey, oldest)
	}
}

func (c *dedupCache) removeLocked(k dedupKey, e *dedupEntry) {
	c.bytes -= e.bytes
	delete(c.entries, k)
}

func (c *dedupCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func completed(e *dedupEntry) bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}
