// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natsrcfiltermap

import (
	"reflect"
	"sync"

	"github.com/cilium/ebpf"
)

// FakeTable is an in-memory Table with *ebpf.Map's copy-in/copy-out
// semantics, for tests that need no kernel or root. Keys must be comparable
// values. Iteration follows insertion order.
type FakeTable struct {
	mu      sync.Mutex
	entries map[any]any
	order   []any
}

// NewFakeTable returns an empty FakeTable.
func NewFakeTable() *FakeTable {
	return &FakeTable{entries: make(map[any]any)}
}

// Put stores value at key.
func (f *FakeTable) Put(key, value any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	return len(f.order)
}

// Iterate returns an Iterator over a snapshot of the entries.
func (f *FakeTable) Iterate() Iterator {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := append([]any(nil), f.order...)
	values := make([]any, len(keys))
	for i, k := range keys {
		values[i] = f.entries[k]
	}
	return &fakeIterator{keys: keys, values: values, idx: -1}
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

// FakePerCPU is an in-memory PerCPUReader: a fixed per-CPU slice per uint32
// index, zero-filled for any index not set.
type FakePerCPU struct {
	mu     sync.Mutex
	CPUs   int
	values map[uint32][]uint64
}

// NewFakePerCPU returns a FakePerCPU reporting cpus values per index.
func NewFakePerCPU(cpus int) *FakePerCPU {
	return &FakePerCPU{CPUs: cpus, values: make(map[uint32][]uint64)}
}

// Set stores perCPU at index.
func (f *FakePerCPU) Set(index uint32, perCPU ...uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[index] = append([]uint64(nil), perCPU...)
}

// Lookup copies index's per-CPU values into valueOut, a *[]uint64.
func (f *FakePerCPU) Lookup(key, valueOut any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	out, ok := valueOut.(*[]uint64)
	if !ok {
		return ebpf.ErrNotSupported
	}
	index, ok := key.(uint32)
	if !ok {
		return ebpf.ErrNotSupported
	}
	v, ok := f.values[index]
	if !ok {
		v = make([]uint64, f.CPUs)
	}
	*out = append([]uint64(nil), v...)
	return nil
}

// FakeTables holds the in-memory maps behind a fake Filter, for assertions
// and for seeding datapath-owned state such as counters and denials.
type FakeTables struct {
	Allow       *FakeTable
	UplinkSlots *FakeTable
	Config      *FakeTable
	Stats       *FakePerCPU
	Denied      *FakeTable
}

// NewFakeFilter returns a Filter backed by fresh in-memory maps, and those
// maps.
func NewFakeFilter() (*Filter, *FakeTables) {
	fakes := &FakeTables{
		Allow:       NewFakeTable(),
		UplinkSlots: NewFakeTable(),
		Config:      NewFakeTable(),
		Stats:       NewFakePerCPU(2),
		Denied:      NewFakeTable(),
	}
	return NewFilter(Tables{
		Allow:       fakes.Allow,
		UplinkSlots: fakes.UplinkSlots,
		Config:      fakes.Config,
		Stats:       fakes.Stats,
		Denied:      fakes.Denied,
	}), fakes
}
