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

// Behavior values for function_table's value field, mirroring the datapath's own
// enum. They are hand-kept in sync because the generator cannot produce a Go
// type for a C enum used only as a literal constant, never as a field the
// compiler retains distinct type information for.
const (
	BehaviorEndDT46 uint32 = 1
	BehaviorEndDT2  uint32 = 2
)

// behaviorForFunction returns the Behavior value corresponding to function, so a
// caller supplies only the block and function and never a Behavior directly.
// That makes a mismatched pair structurally impossible to register through this
// API.
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

// NewFunctionTable wraps table as a FunctionTable. Production callers pass a
// kernel table over the loaded map, or use the registry constructor; tests pass
// a fake.
func NewFunctionTable(table Table) *FunctionTable {
	return &FunctionTable{table: table}
}

// Register writes, or overwrites, the function_table entry for (block,
// function), storing the Behavior derived from function. There is one entry per
// active Block and defined Function.
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

// List returns every entry in function_table, in unspecified order. The raw key
// folds Block and Function together, so List decodes both back out of it.
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
