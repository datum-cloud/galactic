// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nptv6map

import (
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// fakeTable is an in-memory usidmap.Table implementation used across this
// package's tests -- mirrors usidmap's own (unexported, package-local)
// fakeTable in internal/plumbing/ebpf/usidmap/faketable_test.go exactly,
// duplicated here rather than imported since Go test-only helpers in
// another package's _test.go files are not importable.
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
