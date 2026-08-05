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

	// Generation is bumped by Register on every (re-)registration of this
	// Block/Node-ID pair -- e.g. on BGPRouter.Spec.SRv6Locator change --
	// giving R7's multiple-concurrent-Block bookkeeping a way to tell a
	// freshly (re-)confirmed locator apart from one that hasn't been
	// touched by the control daemon in a while. Unlike vrf_table's
	// generation (vrf.go), this is not currently consumed by any
	// Reconcile-style staleness sweep -- the GC controller's scope (design
	// plan §5.3) is vrf_table only -- so LocatorTable exposes no Reconcile
	// method; this field exists because locator_value already carried it
	// from Milestone 2.2, not because this milestone adds new sweep logic
	// for it.
	Generation uint64
}

// LocatorTable is the read/write API for locator_table.
type LocatorTable struct {
	table Table
	clock func() uint64
}

// NewLocatorTable wraps table as a LocatorTable. Production callers pass a
// KernelTable wrapping a loaded *prog.UsidObjects's LocatorTable map (or
// use NewRegistryFromObjects); tests pass a fake Table.
func NewLocatorTable(table Table) *LocatorTable {
	return &LocatorTable{table: table, clock: clockFn}
}

// Register writes (or overwrites) the locator_table entry for (block,
// nodeID), stamping it with this table's current clock reading as its
// Generation. Design plan §4.4: populated "at startup + on locator
// change" by the control daemon, from BGPRouter.Spec.SRv6Locator/.NodeID.
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

// List returns every entry currently in locator_table, in unspecified
// order. Because locator_table's key (Block<<16|NodeID, see
// uformat.NewLocatorKey) folds Block and Node-ID together, List decodes
// both back out of each raw key.
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
