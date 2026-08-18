// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import "github.com/cilium/ebpf"

// Table is the minimal map-operation surface every table type in this
// package is written against, instead of directly against *ebpf.Map. Its
// method set matches *ebpf.Map's own Put/Lookup/Delete/Iterate closely
// enough that KernelTable (below) is a one-line adapter; this package's own
// tests substitute a fake, in-memory implementation to exercise
// shard-config/read-accessor logic without a kernel or root privileges --
// see doc.go for why this is its own declaration rather than an import of
// edgemap's or usidmap's identical interface.
type Table interface {
	// Put creates or overwrites the map entry at key with value.
	Put(key, value any) error

	// Lookup reads the map entry at key into valueOut. It returns
	// ebpf.ErrKeyNotExist (or, for a fake Table, an error satisfying
	// errors.Is(err, ebpf.ErrKeyNotExist)) if key is absent.
	Lookup(key, valueOut any) error

	// Delete removes the map entry at key. It returns ebpf.ErrKeyNotExist
	// (see Lookup) if key is already absent.
	Delete(key any) error

	// Iterate returns an Iterator walking every entry currently in the
	// map, in unspecified order -- matching *ebpf.Map.Iterate's own
	// documented behavior.
	Iterate() Iterator
}

// Iterator matches *ebpf.MapIterator's own Next/Err method set.
type Iterator interface {
	// Next decodes the next key/value pair into keyOut/valueOut and
	// reports whether one was available. Callers must check Err after Next
	// returns false to distinguish "iteration finished" from "an error
	// interrupted iteration."
	Next(keyOut, valueOut any) bool

	// Err returns the first error encountered during iteration, if any.
	Err() error
}

// KernelTable adapts a real, loaded *ebpf.Map -- e.g.
// nat66prog.Nat66Objects's ShardConfigTable/Nat66ConnTable/DropReasons map
// fields, once loaded by internal/plumbing/ebpf/nat66attach -- to the
// Table interface every table type in this package is written against.
type KernelTable struct {
	Map *ebpf.Map
}

func (k KernelTable) Put(key, value any) error       { return k.Map.Put(key, value) }
func (k KernelTable) Lookup(key, valueOut any) error { return k.Map.Lookup(key, valueOut) }
func (k KernelTable) Delete(key any) error           { return k.Map.Delete(key) }
func (k KernelTable) Iterate() Iterator              { return k.Map.Iterate() }
