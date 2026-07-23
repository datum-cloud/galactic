// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"
)

// fakeTable is an in-memory Table implementation used across this
// package's tests -- Milestone 3.3's own exit criterion ("unit tests
// against a mocked map interface"). It stores each value as the concrete
// Go struct Put was given (not raw bytes), copying into/out of callers'
// pointer arguments via reflection to mirror *ebpf.Map's own copy-in/
// copy-out semantics for Put/Lookup/Delete/Iterate, without needing a
// kernel, BTF, or root privileges.
type fakeTable struct {
	entries map[uint64]any
	order   []uint64 // insertion order, for deterministic Iterate/List in tests
}

func newFakeTable() *fakeTable {
	return &fakeTable{entries: make(map[uint64]any)}
}

func fakeTableKey(key any) uint64 {
	k, ok := key.(uint64)
	if !ok {
		panic(fmt.Sprintf("fakeTable: key type %T not supported, want uint64", key))
	}
	return k
}

func (f *fakeTable) Put(key, value any) error {
	k := fakeTableKey(key)
	if _, exists := f.entries[k]; !exists {
		f.order = append(f.order, k)
	}
	f.entries[k] = value
	return nil
}

func (f *fakeTable) Lookup(key, valueOut any) error {
	k := fakeTableKey(key)
	v, ok := f.entries[k]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(v))
	return nil
}

func (f *fakeTable) Delete(key any) error {
	k := fakeTableKey(key)
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	for i, kk := range f.order {
		if kk == k {
			f.order = append(f.order[:i], f.order[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeTable) Iterate() Iterator {
	return &fakeIterator{table: f, idx: -1}
}

// len reports the number of entries currently stored -- a test-only
// convenience, not part of the Table interface.
func (f *fakeTable) len() int { return len(f.order) }

type fakeIterator struct {
	table *fakeTable
	idx   int
}

func (it *fakeIterator) Next(keyOut, valueOut any) bool {
	it.idx++
	if it.idx >= len(it.table.order) {
		return false
	}
	k := it.table.order[it.idx]
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(k))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.table.entries[k]))
	return true
}

func (it *fakeIterator) Err() error { return nil }

// constClock returns a func() uint64 that always returns value -- used
// across this package's tests to give VRFTable/LocatorTable a
// deterministic, test-controlled Generation source instead of a real
// clock. Tests that need the clock to advance mid-test simply reassign
// the table's clock field directly (they run in-package and can reach the
// unexported field) rather than needing a stateful sequence helper.
func constClock(value uint64) func() uint64 {
	return func() uint64 { return value }
}
