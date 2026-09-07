// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// LocatorEntry is one fully decoded locator_table row.
type LocatorEntry struct {
	Block  uint64
	NodeID uint16

	// Generation is bumped on every registration of this Block and Node-ID pair,
	// such as on a locator change, so multi-Block bookkeeping can tell a freshly
	// confirmed locator from one the control daemon has not touched in a while.
	//
	// Unlike vrf_table's, it is consumed by no staleness sweep, the GC scope
	// being vrf_table alone, so this type exposes no Reconcile. The field exists
	// because the kernel value already carries it.
	Generation uint64
}

// LocatorTable is the read/write API for locator_table.
type LocatorTable struct {
	table Table
	clock func() uint64
}

// NewLocatorTable wraps table as a LocatorTable. Production callers pass a
// kernel table over the loaded map, or use the registry constructor; tests pass
// a fake.
func NewLocatorTable(table Table) *LocatorTable {
	return &LocatorTable{table: table, clock: clockFn}
}

// Register writes, or overwrites, the locator_table entry for (block, nodeID),
// stamping it with this table's current clock reading. The control daemon
// populates it at startup and whenever the router's locator changes.
func (t *LocatorTable) Register(block uint64, nodeID uint16) error {
	if err := uformat.ValidateBlock(block); err != nil {
		return fmt.Errorf("usidmap: locator_table: register block=%#x node-id=%#x: %w", block, nodeID, err)
	}
	if err := uformat.ValidateNodeID(nodeID); err != nil {
		return fmt.Errorf("usidmap: locator_table: register block=%#x node-id=%#x: %w", block, nodeID, err)
	}

	key, err := uformat.NewLocatorKey(block, nodeID)
	if err != nil {
		return fmt.Errorf("usidmap: locator_table: register block=%#x node-id=%#x: %w", block, nodeID, err)
	}

	value := prog.UsidLocatorValue{Generation: t.clock()}
	if err := t.table.Put(uint64(key), value); err != nil {
		return fmt.Errorf("usidmap: locator_table: register block=%#x node-id=%#x: %w", block, nodeID, err)
	}
	return nil
}

// Unregister removes the locator_table entry for (block, nodeID), if
// present. Not an error if already absent.
func (t *LocatorTable) Unregister(block uint64, nodeID uint16) error {
	key, err := uformat.NewLocatorKey(block, nodeID)
	if err != nil {
		return fmt.Errorf("usidmap: locator_table: unregister block=%#x node-id=%#x: %w", block, nodeID, err)
	}
	if err := t.table.Delete(uint64(key)); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("usidmap: locator_table: unregister block=%#x node-id=%#x: %w", block, nodeID, err)
	}
	return nil
}

// Get reads the locator_table entry for (block, nodeID), reporting
// whether it exists.
func (t *LocatorTable) Get(block uint64, nodeID uint16) (LocatorEntry, bool, error) {
	key, err := uformat.NewLocatorKey(block, nodeID)
	if err != nil {
		return LocatorEntry{}, false, fmt.Errorf("usidmap: locator_table: get block=%#x node-id=%#x: %w", block, nodeID, err)
	}

	var value prog.UsidLocatorValue
	if err := t.table.Lookup(uint64(key), &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return LocatorEntry{}, false, nil
		}
		return LocatorEntry{}, false, fmt.Errorf("usidmap: locator_table: get block=%#x node-id=%#x: %w", block, nodeID, err)
	}
	return LocatorEntry{Block: block, NodeID: nodeID, Generation: value.Generation}, true, nil
}

// List returns every entry in locator_table, in unspecified order. The raw key
// folds Block and Node-ID together, so List decodes both back out of it.
func (t *LocatorTable) List() ([]LocatorEntry, error) {
	var (
		entries []LocatorEntry
		rawKey  uint64
		value   prog.UsidLocatorValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		entries = append(entries, LocatorEntry{
			Block:      rawKey >> uformat.NodeIDBits,
			NodeID:     uint16(rawKey & (1<<uformat.NodeIDBits - 1)),
			Generation: value.Generation,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("usidmap: locator_table: list: %w", err)
	}
	return entries, nil
}
