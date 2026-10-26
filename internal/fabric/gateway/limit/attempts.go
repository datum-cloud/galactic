// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

import (
	"sync"
	"time"

	"go.datum.net/galactic/internal/fabric/errcode"
)

// AttemptGrace is how long an attempt key outlives its request's
// expiration.
const AttemptGrace = 2 * time.Second

// attemptOverhead approximates one entry's bookkeeping beyond its key and
// digest.
const attemptOverhead = 64

type attempt struct {
	digest string
	until  time.Time
	size   int
}

// Attempts records each admitted attempt key with its argument digest until
// its expiration plus AttemptGrace. It is bounded by entry count and bytes,
// and fails closed when full: a live key is never evicted to admit another.
// It is volatile and lost on restart.
type Attempts struct {
	max, maxBytes int

	mu    sync.Mutex
	bytes int
	m     map[string]attempt
}

// NewAttempts returns an empty cache bounded by l.
func NewAttempts(l Limits) *Attempts {
	return &Attempts{max: l.Attempts, maxBytes: l.AttemptBytes, m: map[string]attempt{}}
}

// Register records key with its arguments' digest until expires plus
// AttemptGrace. A live key is refused with DuplicateRequest when its digest
// matches and DuplicateConflict when it does not; a full cache refuses with
// LimiterUnavailable.
func (a *Attempts) Register(key, digest string, expires, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev, ok := a.m[key]; ok && now.Before(prev.until) {
		if prev.digest == digest {
			return errcode.Status(errcode.DuplicateRequest, "this request ID was already admitted")
		}
		return errcode.Status(errcode.DuplicateConflict, "this request ID was already admitted with other arguments")
	}
	size := len(key) + len(digest) + attemptOverhead
	if len(a.m) >= a.max || a.bytes+size > a.maxBytes {
		a.purge(now)
	}
	if len(a.m) >= a.max || a.bytes+size > a.maxBytes {
		return errcode.Retry(errcode.LimiterUnavailable, "the cell's attempt cache is full", string(ScopeCell), time.Second)
	}
	if prev, ok := a.m[key]; ok {
		a.bytes -= prev.size
	}
	a.m[key] = attempt{digest: digest, until: expires.Add(AttemptGrace), size: size}
	a.bytes += size
	return nil
}

func (a *Attempts) purge(now time.Time) {
	for k, v := range a.m {
		if !now.Before(v.until) {
			delete(a.m, k)
			a.bytes -= v.size
		}
	}
}

// Len returns the number of recorded keys, expired ones included until the
// next purge.
func (a *Attempts) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.m)
}
