// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

import (
	"math"
	"net/netip"
	"sync"
	"time"

	"go.datum.net/galactic/internal/fabric/errcode"
)

// Scope names the limit that refused a charge, as throttling metadata
// reports it. It never carries a project or destination.
type Scope string

// Scopes.
const (
	ScopeCell        Scope = "cell"
	ScopeProject     Scope = "project"
	ScopeDestination Scope = "destination"
	ScopeQueue       Scope = "queue"
)

// class is one family of buckets sharing a rate and, for keyed families, a
// key bound.
type class int

const (
	requestCell class = iota
	requestProject
	packetCell
	packetPrincipal
	packetHost
	packetPrefix
)

type bucketKey struct {
	class class
	id    string
}

type bucket struct {
	tokens float64
	at     time.Time
}

// Buckets are the cell's request and packet token buckets. Every bucket
// starts empty at the instant of the last Reset and refills from there, so a
// key first seen later starts with at most min(burst, rate × time since the
// reset). A charge debits every bucket it names or none, and never takes a
// bucket below zero. A key is discarded only once its bucket has fully
// refilled, so no debt is ever forgotten; when a key family is full of
// buckets still refilling, a new key is refused with LimiterUnavailable.
type Buckets struct {
	limits Limits

	mu      sync.Mutex
	start   time.Time
	buckets map[bucketKey]*bucket
	// keyed counts the buckets of the project/principal and destination
	// families.
	projectKeys, destinationKeys int
}

// NewBuckets returns empty buckets, refilling from now.
func NewBuckets(l Limits, now time.Time) *Buckets {
	b := &Buckets{limits: l}
	b.Reset(now)
	return b
}

// Reset empties every bucket and restarts refilling from now.
func (b *Buckets) Reset(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.start = now
	b.buckets = map[bucketKey]*bucket{}
	b.projectKeys, b.destinationKeys = 0, 0
}

func (b *Buckets) rate(c class) Rate {
	switch c {
	case requestCell:
		return b.limits.RequestCell
	case requestProject:
		return b.limits.RequestProject
	case packetCell:
		return b.limits.PacketCell
	case packetPrincipal:
		return b.limits.PacketPrincipal
	case packetHost:
		return b.limits.PacketHost
	}
	return b.limits.PacketPrefix
}

func scopeOf(c class) Scope {
	switch c {
	case requestCell, packetCell:
		return ScopeCell
	case requestProject, packetPrincipal:
		return ScopeProject
	}
	return ScopeDestination
}

// level returns k's tokens at now.
func (b *Buckets) level(k bucketKey, bk *bucket, now time.Time) float64 {
	r := b.rate(k.class)
	elapsed := max(now.Sub(bk.at).Seconds(), 0)
	return math.Min(r.Burst, bk.tokens+r.PerSecond*elapsed)
}

// ChargeRequest debits one request token from the cell and from project.
func (b *Buckets) ChargeRequest(project string, now time.Time) error {
	return b.charge(1, now, bucketKey{requestCell, ""}, bucketKey{requestProject, project})
}

// ChargePackets debits packets from the cell, from principal when it is not
// empty, and from dst's host and containing prefix (IPv4 /24, IPv6 /64).
func (b *Buckets) ChargePackets(principal string, dst netip.Addr, packets int, now time.Time) error {
	host, prefix := DestinationKeys(dst)
	keys := []bucketKey{{packetCell, ""}, {packetHost, host}, {packetPrefix, prefix}}
	if principal != "" {
		keys = append(keys, bucketKey{packetPrincipal, principal})
	}
	return b.charge(float64(packets), now, keys...)
}

// DestinationKeys returns dst's host key and its containing prefix key.
func DestinationKeys(dst netip.Addr) (host, prefix string) {
	dst = dst.Unmap()
	bits := 64
	if dst.Is4() {
		bits = 24
	}
	p, _ := dst.Prefix(bits)
	return netip.PrefixFrom(dst, dst.BitLen()).String(), p.String()
}

// charge debits n from every bucket in keys, or from none. A shortage is
// refused with Throttled and a retry delay of the largest deficit/rate
// among the short buckets, scoped to that bucket's family.
func (b *Buckets) charge(n float64, now time.Time, keys ...bucketKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	found := make([]*bucket, len(keys))
	for i, k := range keys {
		bk, err := b.lookup(k, now)
		if err != nil {
			return err
		}
		found[i] = bk
	}
	var wait float64
	var scope Scope
	for i, k := range keys {
		if have := b.level(k, found[i], now); have < n {
			if d := (n - have) / b.rate(k.class).PerSecond; d > wait {
				wait, scope = d, scopeOf(k.class)
			}
		}
	}
	if scope != "" {
		return errcode.Retry(errcode.Throttled, "an admission budget is exhausted", string(scope),
			time.Duration(math.Ceil(wait*float64(time.Second))))
	}
	for i, k := range keys {
		// A caller holding an older now never moves a bucket's clock back.
		at := now
		if found[i].at.After(at) {
			at = found[i].at
		}
		found[i].tokens = b.level(k, found[i], at) - n
		found[i].at = at
	}
	return nil
}

// lookup returns k's bucket, creating it empty at the reset instant. A full
// key family first discards one fully refilled bucket; with none, the new
// key is refused.
func (b *Buckets) lookup(k bucketKey, now time.Time) (*bucket, error) {
	if bk, ok := b.buckets[k]; ok {
		return bk, nil
	}
	count, limit := b.family(k.class)
	if count != nil && *count >= limit && !b.evict(k.class, now) {
		return nil, errcode.Retry(errcode.LimiterUnavailable, "the cell's limiter has no room for a new key",
			string(scopeOf(k.class)), time.Second)
	}
	bk := &bucket{at: b.start}
	b.buckets[k] = bk
	if count != nil {
		*count++
	}
	return bk, nil
}

// family returns the counter and bound of c's key family, or nil for a
// fixed cell bucket.
func (b *Buckets) family(c class) (*int, int) {
	switch c {
	case requestProject, packetPrincipal:
		return &b.projectKeys, b.limits.ProjectKeys
	case packetHost, packetPrefix:
		return &b.destinationKeys, b.limits.DestinationKeys
	}
	return nil, 0
}

// evict discards one fully refilled bucket of c's key family.
func (b *Buckets) evict(c class, now time.Time) bool {
	count, _ := b.family(c)
	for k, bk := range b.buckets {
		if other, _ := b.family(k.class); other != count {
			continue
		}
		if b.level(k, bk, now) >= b.rate(k.class).Burst {
			delete(b.buckets, k)
			*count--
			return true
		}
	}
	return false
}

// Keys returns how many project/principal and destination buckets exist.
func (b *Buckets) Keys() (project, destination int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.projectKeys, b.destinationKeys
}
