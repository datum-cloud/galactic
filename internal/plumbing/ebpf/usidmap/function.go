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

// Behavior values for function_table's value field, mirroring usid.c's
// `enum function_behavior` (BEHAVIOR_END_DT46/BEHAVIOR_END_DT2). These are
// hand-kept in sync with usid.c because bpf2go's -type flag cannot
// generate a Go type for a C enum that is only ever used as a literal
// constant, never as a variable/field the compiler retains distinct BTF
// for (see prog/doc.go's go:generate comment, and prog/usid_test.go's own
// hand-kept drop_reason constants for the identical reason).
const (
	BehaviorEndDT46 uint32 = 1
	BehaviorEndDT2  uint32 = 2
)

// behaviorForFunction returns the function_table Behavior value
// corresponding to function, so FunctionTable.Register's caller supplies
// only (block, function) -- never a Behavior directly -- making a
// mismatched Function/Behavior pair (e.g. Function 0xE stored against
// BEHAVIOR_END_DT2) structurally impossible to register through this API.
func behaviorForFunction(function uint8) (uint32, error) {
	switch function {
	case uformat.FunctionEndDT46:
		return BehaviorEndDT46, nil
	case uformat.FunctionEndDT2:
		return BehaviorEndDT2, nil
	default:
		return 0, fmt.Errorf("usidmap: function %#x is not a defined Function value (want %#x or %#x)",
			function, uint8(uformat.FunctionEndDT46), uint8(uformat.FunctionEndDT2))
	}
}

// FunctionEntry is one fully decoded function_table row.
type FunctionEntry struct {
	Block    uint64
	Function uint8
	Behavior uint32
}

// FunctionTable is the read/write API for function_table.
type FunctionTable struct {
	table Table
}

// NewFunctionTable wraps table as a FunctionTable. Production callers pass
// a KernelTable wrapping a loaded *prog.UsidObjects's FunctionTable map (or
// use NewRegistryFromObjects); tests pass a fake Table.
func NewFunctionTable(table Table) *FunctionTable {
	return &FunctionTable{table: table}
}

// Register writes (or overwrites) the function_table entry for (block,
// function), storing the Behavior value behaviorForFunction derives from
// function -- one entry per (active uSID Block x defined Function), per
// design plan §4.4.
func (t *FunctionTable) Register(block uint64, function uint8) error {
	if err := uformat.ValidateBlock(block); err != nil {
		return fmt.Errorf("usidmap: function_table: register block=%#x function=%#x: %w", block, function, err)
	}
	behavior, err := behaviorForFunction(function)
	if err != nil {
		return fmt.Errorf("usidmap: function_table: register block=%#x function=%#x: %w", block, function, err)
	}

	key, err := uformat.NewFunctionKey(block, function)
	if err != nil {
		return fmt.Errorf("usidmap: function_table: register block=%#x function=%#x: %w", block, function, err)
	}

	value := prog.UsidFunctionValue{Behavior: behavior}
	if err := t.table.Put(uint64(key), value); err != nil {
		return fmt.Errorf("usidmap: function_table: register block=%#x function=%#x: %w", block, function, err)
	}
	return nil
}

// Unregister removes the function_table entry for (block, function), if
// present. Not an error if already absent.
func (t *FunctionTable) Unregister(block uint64, function uint8) error {
	key, err := uformat.NewFunctionKey(block, function)
	if err != nil {
		return fmt.Errorf("usidmap: function_table: unregister block=%#x function=%#x: %w", block, function, err)
	}
	if err := t.table.Delete(uint64(key)); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("usidmap: function_table: unregister block=%#x function=%#x: %w", block, function, err)
	}
	return nil
}

// Get reads the function_table entry for (block, function), reporting
// whether it exists.
func (t *FunctionTable) Get(block uint64, function uint8) (FunctionEntry, bool, error) {
	key, err := uformat.NewFunctionKey(block, function)
	if err != nil {
		return FunctionEntry{}, false, fmt.Errorf(
			"usidmap: function_table: get block=%#x function=%#x: %w", block, function, err)
	}

	var value prog.UsidFunctionValue
	if err := t.table.Lookup(uint64(key), &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return FunctionEntry{}, false, nil
		}
		return FunctionEntry{}, false, fmt.Errorf(
			"usidmap: function_table: get block=%#x function=%#x: %w", block, function, err)
	}
	return FunctionEntry{Block: block, Function: function, Behavior: value.Behavior}, true, nil
}

// List returns every entry currently in function_table, in unspecified
// order. Because function_table's key (Block<<4|Function, see
// uformat.NewFunctionKey) folds Block and Function together, List decodes
// both back out of each raw key.
func (t *FunctionTable) List() ([]FunctionEntry, error) {
	var (
		entries []FunctionEntry
		rawKey  uint64
		value   prog.UsidFunctionValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		entries = append(entries, FunctionEntry{
			Block:    rawKey >> uformat.FunctionBits,
			Function: uint8(rawKey & (1<<uformat.FunctionBits - 1)),
			Behavior: value.Behavior,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("usidmap: function_table: list: %w", err)
	}
	return entries, nil
}
