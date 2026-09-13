// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natmap

import "github.com/cilium/ebpf"

// Table is the minimal map-operation surface every table type in this package is
// written against, rather than a loaded map directly. Its method set is close
// enough to the real map's that KernelTable is a one-line adapter, and tests
// substitute an in-memory fake to exercise this package's logic without a kernel
// or root. See the package doc comment for why it is declared here rather than
// imported from a sibling.
type Table interface {
	// Put creates or overwrites the map entry at key with value.
	Put(key, value any) error

	// Lookup reads the entry at key into valueOut, returning an error matching
	// ebpf.ErrKeyNotExist when key is absent.
	Lookup(key, valueOut any) error

	// Delete removes the map entry at key. It returns ebpf.ErrKeyNotExist
	// (see Lookup) if key is already absent.
	Delete(key any) error

	// Iterate returns an Iterator over every entry currently in the map, in
	// unspecified order.
	Iterate() Iterator
}

// Iterator matches *ebpf.MapIterator's own Next/Err method set.
type Iterator interface {
	// Next decodes the next pair into keyOut and valueOut and reports whether
	// one was available. Callers must check Err after it returns false, to tell
	// a finished iteration from an interrupted one.
	Next(keyOut, valueOut any) bool

	// Err returns the first error encountered during iteration, if any.
	Err() error
}

// KernelTable adapts a real, loaded map to the Table interface every table type
// in this package is written against.
type KernelTable struct {
	Map *ebpf.Map
}

func (k KernelTable) Put(key, value any) error       { return k.Map.Put(key, value) }
func (k KernelTable) Lookup(key, valueOut any) error { return k.Map.Lookup(key, valueOut) }
func (k KernelTable) Delete(key any) error           { return k.Map.Delete(key) }
func (k KernelTable) Iterate() Iterator              { return k.Map.Iterate() }
