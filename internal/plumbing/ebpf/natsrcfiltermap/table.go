// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natsrcfiltermap

import "github.com/cilium/ebpf"

// Table is the map-operation surface Filter is written against. A loaded
// *ebpf.Map satisfies it through KernelTable.
type Table interface {
	// Put creates or overwrites the entry at key with value.
	Put(key, value any) error

	// Lookup reads the entry at key into valueOut, returning an error matching
	// ebpf.ErrKeyNotExist when key is absent.
	Lookup(key, valueOut any) error

	// Delete removes the entry at key, returning an error matching
	// ebpf.ErrKeyNotExist when key is absent.
	Delete(key any) error

	// Iterate returns an Iterator over every entry, in unspecified order.
	Iterate() Iterator
}

// Iterator matches *ebpf.MapIterator's Next/Err method set.
type Iterator interface {
	// Next decodes the next pair into keyOut and valueOut and reports whether
	// one was available.
	Next(keyOut, valueOut any) bool

	// Err returns the first error encountered during iteration.
	Err() error
}

// PerCPUReader reads one per-CPU array slot into a slice with one value per
// CPU. A loaded per-CPU *ebpf.Map satisfies it directly.
type PerCPUReader interface {
	Lookup(key, valueOut any) error
}

// KernelTable adapts a loaded map to Table.
type KernelTable struct {
	Map *ebpf.Map
}

func (k KernelTable) Put(key, value any) error       { return k.Map.Put(key, value) }
func (k KernelTable) Lookup(key, valueOut any) error { return k.Map.Lookup(key, valueOut) }
func (k KernelTable) Delete(key any) error           { return k.Map.Delete(key) }
func (k KernelTable) Iterate() Iterator              { return k.Map.Iterate() }
