// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package maglev

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
)

// Backend is one candidate a Table can assign lookup slots to. Key must be
// stable and unique within a Table's backend set: it is the sole input to both
// of a backend's permutation hashes, so two backends sharing a Key collide onto
// the same permutation and are indistinguishable here.
type Backend interface {
	Key() string
}

// offsetSeed and skipSeed are fixed salts distinguishing the two independent
// hashes the permutation needs, derived from one hash function applied to the
// key plus a different seed rather than two unrelated algorithms.
const (
	offsetSeed uint64 = 0xda7a5eed0ffce7e5
	skipSeed   uint64 = 0x5eedda7a1ceb00c5
)

// Table is a Maglev consistent-hash lookup table over a fixed backend set. See
// the package doc comment for the properties: deterministic given its inputs,
// with a bounded disruption fraction when the backend set changes.
type Table struct {
	size     int
	entries  []Backend
	backends []Backend // sorted by Key(), for deterministic iteration/inspection
}

// New builds a Table assigning size lookup slots across backends.
//
// size must be prime, which the disruption bound's permutation-cycle argument
// requires, and the paper recommends at least 100 times the backend count for
// that bound to hold in practice. New does not enforce the ratio, a small fixed
// table in a test being a legitimate use, but does reject a size too small to
// fit one slot per backend, and any non-prime size.
//
// backends must be non-empty with unique keys; anything else is an error rather
// than a silently degenerate table. Input order does not matter, backends being
// sorted by key internally, so every caller building from the same set produces
// the byte-identical table whatever order it observed them in.
func New(backends []Backend, size int) (*Table, error) {
	if len(backends) == 0 {
		return nil, errors.New("maglev: at least one backend is required")
	}
	if size < len(backends) {
		return nil, fmt.Errorf("maglev: table size %d smaller than backend count %d", size, len(backends))
	}
	if !IsPrime(size) {
		return nil, fmt.Errorf("maglev: table size %d is not prime", size)
	}

	sorted := make([]Backend, len(backends))
	copy(sorted, backends)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key() < sorted[j].Key() })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Key() == sorted[i-1].Key() {
			return nil, fmt.Errorf("maglev: duplicate backend key %q", sorted[i].Key())
		}
	}

	t := &Table{size: size, backends: sorted, entries: make([]Backend, size)}
	t.fill()
	return t, nil
}

// fill runs the round-robin permutation-preference algorithm: each backend
// repeatedly proposes its next-preferred free slot, computed lazily from its
// own offset and skip rather than materializing a full permutation matrix,
// until every slot is claimed.
func (t *Table) fill() {
	n := len(t.backends)
	offset := make([]uint64, n)
	skip := make([]uint64, n)
	next := make([]uint64, n) // this backend's next permutation step to try
	claimed := make([]bool, t.size)

	size := uint64(t.size) //nolint:gosec // size validated positive and prime above
	for i, b := range t.backends {
		offset[i] = hashKey(b.Key(), offsetSeed) % size
		skip[i] = hashKey(b.Key(), skipSeed)%(size-1) + 1
	}

	filled := 0
	for filled < t.size {
		for i, b := range t.backends {
			var slot uint64
			for {
				slot = (offset[i] + next[i]*skip[i]) % size
				next[i]++
				if !claimed[slot] {
					break
				}
			}
			claimed[slot] = true
			t.entries[slot] = b
			filled++
			if filled == t.size {
				break
			}
		}
	}
}

// Lookup returns the backend assigned to key's slot. Every Table built from the
// same inputs resolves the same key to the same backend.
func (t *Table) Lookup(key uint64) Backend {
	return t.entries[key%uint64(t.size)]
}

// Size returns the table's configured slot count.
func (t *Table) Size() int { return t.size }

// Backends returns the backend set this table was built from, sorted by
// Key(). Callers must not mutate the returned slice.
func (t *Table) Backends() []Backend { return t.backends }

// IsPrime reports whether n is prime; anything below 2 is not. Trial division
// rather than a probabilistic test: table sizes here are modest and chosen once
// per rule change rather than per packet, so correctness matters more than the
// marginal speed.
func IsPrime(n int) bool {
	if n < 2 {
		return false
	}
	if n%2 == 0 {
		return n == 2
	}
	for d := 3; d*d <= n; d += 2 {
		if n%d == 0 {
			return false
		}
	}
	return true
}

// hashKey derives one of the two hash values the permutation needs, from a
// single hash over the key's bytes followed by the seed's. A different seed
// produces an uncorrelated second hash without a second algorithm.
func hashKey(key string, seed uint64) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	var seedBuf [8]byte
	binary.BigEndian.PutUint64(seedBuf[:], seed)
	_, _ = h.Write(seedBuf[:])
	return h.Sum64()
}
