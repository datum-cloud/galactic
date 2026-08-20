// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import (
	"reflect"

	"github.com/cilium/ebpf"
)

// fakeTable is an in-memory Table implementation used across this
// package's tests, keyed by `any` (rather than usidmap's fakeTable, which
// assumes every key is a uint64) since this package's two tables use two
// different key types: shard_config_table's fixed uint32(0) and
// nat66_conn_table's nat66prog.Nat66ConnKey struct. It stores each value as
// the concrete Go struct Put was given, copying into/out of callers'
// pointer arguments via reflection to mirror *ebpf.Map's own copy-in/
// copy-out semantics for Put/Lookup/Delete/Iterate, without needing a
// kernel, BTF, or root privileges.
type fakeTable struct {
	entries map[any]any
	order   []any // insertion order, for deterministic Iterate/List in tests
}

func newFakeTable() *fakeTable {
	return &fakeTable{entries: make(map[any]any)}
}

func (f *fakeTable) Put(key, value any) error {
	if _, exists := f.entries[key]; !exists {
		f.order = append(f.order, key)
	}
	f.entries[key] = value
	return nil
}

func (f *fakeTable) Lookup(key, valueOut any) error {
	v, ok := f.entries[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(v))
	return nil
}

func (f *fakeTable) Delete(key any) error {
	if _, ok := f.entries[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, key)
	for i, kk := range f.order {
		if kk == key {
			f.order = append(f.order[:i], f.order[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeTable) Iterate() Iterator {
	return &fakeIterator{table: f, idx: -1}
}

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

var _ Table = (*fakeTable)(nil)

// fakeDropReasonsReader is an in-memory DropReasonsReader for
// dropreasons_test.go, keyed by drop-reason index with a fixed per-CPU
// slice per index -- enough to exercise SumDropReason/DropReasonTotals'
// summing logic without a kernel.
type fakeDropReasonsReader struct {
	perCPU map[uint32][]uint64
	err    error
}

func (f *fakeDropReasonsReader) Lookup(key, valueOut any) error {
	if f.err != nil {
		return f.err
	}
	k := key.(uint32) //nolint:forcetypeassert // test-only fake, always called with uint32
	*valueOut.(*[]uint64) = f.perCPU[k]
	return nil
}
