// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package maglev

import (
	"fmt"
	"testing"
)

type testBackend string

func (b testBackend) Key() string { return string(b) }

func backends(keys ...string) []Backend {
	out := make([]Backend, len(keys))
	for i, k := range keys {
		out[i] = testBackend(k)
	}
	return out
}

func TestIsPrime(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want bool
	}{
		{"Negative", -1, false},
		{"Zero", 0, false},
		{"One", 1, false},
		{"Two", 2, true},
		{"Three", 3, true},
		{"Four", 4, false},
		{"KnownPrime", 65537, true},
		{"KnownComposite", 65536, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrime(tt.n); got != tt.want {
				t.Errorf("IsPrime(%d) = %v, want %v", tt.n, got, tt.want)
			}
		})
	}
}

func TestNew_Errors(t *testing.T) {
	tests := []struct {
		name      string
		backends  []Backend
		size      int
		wantError bool
	}{
		{"Empty", backends(), 101, true},
		{"TooSmall", backends("a", "b"), 1, true},
		{"NotPrime", backends("a", "b"), 100, true},
		{"DuplicateKey", backends("a", "a"), 101, true},
		{"Valid", backends("a", "b", "c"), 101, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.backends, tt.size)
			if (err != nil) != tt.wantError {
				t.Errorf("New() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

// TestNew_Deterministic verifies that two tables built from the same
// backend set in different input orders produce the byte-identical
// assignment — the property every gateway node's independent Table
// construction depends on.
func TestNew_Deterministic(t *testing.T) {
	const size = 1009
	a, err := New(backends("b1", "b2", "b3", "b4"), size)
	if err != nil {
		t.Fatalf("New(a): %v", err)
	}
	b, err := New(backends("b4", "b3", "b2", "b1"), size)
	if err != nil {
		t.Fatalf("New(b): %v", err)
	}

	for key := range uint64(5000) {
		if a.Lookup(key).Key() != b.Lookup(key).Key() {
			t.Fatalf("Lookup(%d) diverged: %q vs %q", key, a.Lookup(key).Key(), b.Lookup(key).Key())
		}
	}
}

// TestTable_EveryEntryAssigned verifies the fill algorithm leaves no slot
// unclaimed (a nil Backend would panic Lookup's caller).
func TestTable_EveryEntryAssigned(t *testing.T) {
	table, err := New(backends("b1", "b2", "b3"), 1009)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i, e := range table.entries {
		if e == nil {
			t.Fatalf("entries[%d] is nil", i)
		}
	}
}

// TestTable_LookupStable verifies repeated Lookup calls for the identical
// key against the identical table always return the identical backend.
func TestTable_LookupStable(t *testing.T) {
	table, err := New(backends("b1", "b2", "b3"), 1009)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := table.Lookup(42)
	for range 10 {
		if got := table.Lookup(42); got.Key() != want.Key() {
			t.Errorf("Lookup(42) = %q, want %q", got.Key(), want.Key())
		}
	}
}

// TestTable_DisruptionBound is the classic Maglev property test (the paper's
// own evaluation, §5.3): removing one backend from an N-backend set should
// only reassign approximately 1/N of keys, not reshuffle the whole table the
// way a plain hash(key) % len(backends) scheme would. Some slack over the
// exact 1/N is allowed (this is an approximate bound, not an exact one).
func TestTable_DisruptionBound(t *testing.T) {
	const (
		n         = 50
		size      = 65537
		sampleKey = 20000
	)
	keys := make([]string, n)
	for i := range n {
		keys[i] = fmt.Sprintf("backend-%d", i)
	}

	before, err := New(backends(keys...), size)
	if err != nil {
		t.Fatalf("New(before): %v", err)
	}
	after, err := New(backends(keys[:n-1]...), size) // drop the last backend
	if err != nil {
		t.Fatalf("New(after): %v", err)
	}

	reassigned := 0
	for key := range uint64(sampleKey) {
		if before.Lookup(key).Key() != after.Lookup(key).Key() {
			reassigned++
		}
	}

	gotFraction := float64(reassigned) / float64(sampleKey)
	// Expect ~1/n; allow generous slack (2/n) for statistical noise at this
	// sample size rather than asserting the exact theoretical bound.
	maxFraction := 2.0 / float64(n)
	if gotFraction > maxFraction {
		t.Errorf("reassigned fraction = %.4f, want <= %.4f (~1/%d, with slack)", gotFraction, maxFraction, n)
	}
}

// TestTable_BackendsSortedByKey verifies Backends() returns a deterministic,
// sorted view regardless of the constructor's input order.
func TestTable_BackendsSortedByKey(t *testing.T) {
	table, err := New(backends("z", "a", "m"), 101)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := table.Backends()
	want := []string{"a", "m", "z"}
	for i, w := range want {
		if got[i].Key() != w {
			t.Errorf("Backends()[%d] = %q, want %q", i, got[i].Key(), w)
		}
	}
}
