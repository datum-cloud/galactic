// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"reflect"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// fakeTable is an in-memory usidmap.Table implementation for this
// package's tests -- copied from vipxlatmap's own identical fakeTable
// (see that package's doc comment for why a comparable `any` key, not a
// hardcoded uint64: this package's own key, prog.UsidEgressRouteKey, is a
// struct too).
type fakeTable struct {
	entries map[any]any
	order   []any
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
