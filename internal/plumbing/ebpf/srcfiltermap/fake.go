// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfiltermap

import (
	"reflect"
	"sync"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// NewFake returns a Filter over in-memory tables, and the tables themselves so
// a test can seed datapath-written state such as stats or denied sources. The
// fake matches keys exactly; it does not perform longest-prefix matching.
//
// Stats values are []uint64 per-CPU slices keyed by uint32 slot, and denied
// sources are prog.UsidSrcDeniedValue keyed by prog.UsidSrcDeniedKey.
func NewFake() (*Filter, Tables) {
	t := Tables{
		Allow:       NewFakeTable(),
		UplinkSlots: NewFakeTable(),
		Config:      NewFakeTable(),
		Stats:       NewFakeTable(),
		Denied:      NewFakeTable(),
	}
	return New(t), t
}

// FakeTable is an in-memory usidmap.Table, safe for concurrent use. Iteration
// runs over a snapshot in insertion order.
type FakeTable struct {
	mu      sync.Mutex
	entries map[any]any
	order   []any
	// PutErr, when set, is returned by every Put instead of storing.
	PutErr error
}

// NewFakeTable returns an empty FakeTable.
func NewFakeTable() *FakeTable {
	return &FakeTable{entries: make(map[any]any)}
}

// Put stores value at key, or returns PutErr if set.
func (f *FakeTable) Put(key, value any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.PutErr != nil {
		return f.PutErr
	}
	if _, exists := f.entries[key]; !exists {
		f.order = append(f.order, key)
	}
	f.entries[key] = value
	return nil
}

// Lookup copies the value at key into valueOut, or returns
// ebpf.ErrKeyNotExist.
func (f *FakeTable) Lookup(key, valueOut any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.entries[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(v))
	return nil
}

// Delete removes key, or returns ebpf.ErrKeyNotExist.
func (f *FakeTable) Delete(key any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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

// Len returns the number of entries.
func (f *FakeTable) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

// Iterate returns an iterator over a snapshot of the table.
func (f *FakeTable) Iterate() usidmap.Iterator {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := &fakeIterator{idx: -1}
	for _, k := range f.order {
		it.keys = append(it.keys, k)
		it.values = append(it.values, f.entries[k])
	}
	return it
}

type fakeIterator struct {
	keys   []any
	values []any
	idx    int
}

func (it *fakeIterator) Next(keyOut, valueOut any) bool {
	it.idx++
	if it.idx >= len(it.keys) {
		return false
	}
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(it.keys[it.idx]))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.values[it.idx]))
	return true
}

func (it *fakeIterator) Err() error { return nil }
