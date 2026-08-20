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

// Backend is one candidate a Table can assign lookup-table slots to. Key
// must be stable and unique within one Table's backend set — it is the sole
// input to both of a backend's permutation hashes (offsetSeed/skipSeed
// below), so two backends sharing a Key would collide onto the identical
// permutation and are not distinguishable by this package.
type Backend interface {
	Key() string
}

// offsetSeed/skipSeed are fixed salts distinguishing the two independent
// hashes Maglev's permutation generation needs (the paper's h1/h2) from one
// underlying hash function (fnv1a) applied to Key() + a different seed,
// rather than requiring two unrelated hash algorithms.
const (
	offsetSeed uint64 = 0xda7a5eed0ffce7e5
	skipSeed   uint64 = 0x5eedda7a1ceb00c5
)

// Table is a Maglev consistent-hash lookup table over a fixed backend set.
// See doc.go for the properties this construction gives: deterministic
// given (backends, size), and a bounded (~1/N) disruption fraction on
// backend-set changes.
type Table struct {
	size     int
	entries  []Backend
	backends []Backend // sorted by Key(), for deterministic iteration/inspection
}

// New builds a Table assigning size lookup slots across backends. size must
// be prime (see IsPrime) and, per the Maglev paper, at least 100x
// len(backends) for the disruption-bound property to hold in practice — New
// does not itself enforce the 100x guidance (a caller validating a small
// fixed table against a handful of backends in a test is a legitimate use
// that would otherwise be rejected), but does reject a size that cannot even
// fit one slot per backend, and any non-prime size (the permutation-cycle
// argument the paper's disruption bound rests on requires it).
//
// backends must be non-empty and every Key() unique; New returns an error
// otherwise rather than silently building a degenerate table. The input
// slice order does not affect the result — backends are sorted by Key()
// internally, so every caller building a Table from the identical backend
// set (regardless of the order each independently observed it in, e.g. from
// unordered CRD list results) produces the byte-identical table.
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

// fill runs the paper's round-robin permutation-preference algorithm
// (§3.4): each backend repeatedly proposes its next-preferred still-free
// slot (computed lazily from its own offset/skip, never materializing a
// full n-by-size permutation matrix) until every slot is claimed.
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

// Lookup returns the backend assigned to key's slot (key mod the table
// size). Every Table built from the identical (backends, size) input
// resolves the identical key to the identical backend — see doc.go.
func (t *Table) Lookup(key uint64) Backend {
	return t.entries[key%uint64(t.size)]
}

// Size returns the table's configured slot count.
func (t *Table) Size() int { return t.size }

// Backends returns the backend set this table was built from, sorted by
// Key(). Callers must not mutate the returned slice.
func (t *Table) Backends() []Backend { return t.backends }

// IsPrime reports whether n is a prime number (n < 2 is never prime). Trial
// division is intentionally used rather than a probabilistic test: table
// sizes in this package's use are modest (tens of thousands at most, chosen
// once per rule/shard-set change, not per packet), and correctness matters
// more than the marginal speed of a Miller-Rabin implementation here.
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

// hashKey derives one of the two independent hash values Maglev's
// permutation generation needs from a single fnv1a hash of key's own bytes
// followed by seed's own 8 bytes — a different seed produces an
// uncorrelated-in-practice second hash without depending on a second,
// unrelated hash algorithm.
func hashKey(key string, seed uint64) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	var seedBuf [8]byte
	binary.BigEndian.PutUint64(seedBuf[:], seed)
	_, _ = h.Write(seedBuf[:])
	return h.Sum64()
}
