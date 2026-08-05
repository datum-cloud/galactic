// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// fakeTable is an in-memory usidmap.Table implementation for this
// package's tests, the same technique
// internal/plumbing/ebpf/usidmap/faketable_test.go uses (unexported there,
// so not reusable across package boundaries -- reimplemented here rather
// than promoted to an exported helper, to keep that package's own test
// surface unchanged).
type fakeTable struct {
	entries map[uint64]any
	order   []uint64
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

func (f *fakeTable) Iterate() usidmap.Iterator {
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

// fakeDropReasons is an in-memory DropReasonsReader for tests -- a plain
// map from drop_reasons index to a single "per-CPU" value, since tests
// don't need to exercise the real per-CPU summing behavior (that is
// exercised by kernel_test.go's real-map integration test).
type fakeDropReasons map[uint32]uint64

func (f fakeDropReasons) Lookup(key, valueOut any) error {
	k, ok := key.(uint32)
	if !ok {
		panic(fmt.Sprintf("fakeDropReasons: key type %T not supported, want uint32", key))
	}
	out, ok := valueOut.(*[]uint64)
	if !ok {
		panic(fmt.Sprintf("fakeDropReasons: valueOut type %T not supported, want *[]uint64", valueOut))
	}
	*out = []uint64{f[k]}
	return nil
}
