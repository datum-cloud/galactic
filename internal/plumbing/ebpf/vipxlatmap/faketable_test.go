// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import (
	"reflect"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// fakeTable is an in-memory usidmap.Table implementation for this
// package's tests, mirroring internal/plumbing/ebpf/usidmap's own
// faketable_test.go -- generalized to a comparable `any` key instead of a
// hardcoded uint64, since vip_xlat_table's key is a struct
// (prog.UsidVipXlatKey), not a plain uint64 like vrf_table's. It stores
// each value as the concrete Go struct Put was given (not raw bytes),
// copying into/out of callers' pointer arguments via reflection to mirror
// *ebpf.Map's own copy-in/copy-out semantics, without needing a kernel,
// BTF, or root privileges.
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
	for i, k := range f.order {
		if k == key {
			f.order = append(f.order[:i], f.order[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeTable) Iterate() usidmap.Iterator {
	return &fakeIterator{table: f, idx: -1}
}

// len reports the number of entries currently stored -- a test-only
// convenience, not part of the usidmap.Table interface.
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

// constClock returns a func() uint64 that always returns value -- mirrors
// usidmap's own identical test helper, used to give VipXlatTable a
// deterministic, test-controlled Generation source instead of a real clock.
func constClock(value uint64) func() uint64 {
	return func() uint64 { return value }
}
