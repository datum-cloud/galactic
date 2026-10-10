// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// GroupSnapshotSpec is the spec of one egress_shard_groups inner map, which
// must match the compiled map's inner template exactly: the kernel refuses to
// store an inner map of any other shape.
var GroupSnapshotSpec = ebpf.MapSpec{
	Name:       "egress_shard_gr",
	Type:       ebpf.Array,
	KeySize:    4,
	ValueSize:  uint32(binary.Size(prog.UsidEgressShardGroupValue{})), //nolint:gosec // a fixed struct size
	MaxEntries: 1,
}

// snapshotLookupAttempts bounds Load's retries when an inner map is replaced
// and freed between reading its ID and opening it.
const snapshotLookupAttempts = 5

// KernelGroupStore publishes group snapshots into egress_shard_groups, an
// ARRAY_OF_MAPS. Each publication creates a fresh inner map, fills it, and
// swaps it into the outer slot with one update. The swap replaces an
// RCU-protected pointer: a packet sees the old snapshot or the new one, never
// a mix, and the kernel frees the old inner map once no program can still be
// reading it. A published inner map is never written again.
//
// The three steps fail independently: creating the inner map, writing its
// value, and the swap. A failure before the swap publishes nothing.
type KernelGroupStore struct {
	outer *ebpf.Map

	// The three publication steps, each a test override point so a fault can
	// be injected at every boundary.
	newMap     func(*ebpf.MapSpec) (*ebpf.Map, error)
	writeInner func(inner *ebpf.Map, value *prog.UsidEgressShardGroupValue) error
	swap       func(outer *ebpf.Map, groupID uint32, inner *ebpf.Map) error
}

// NewKernelGroupStore wraps a loaded or pinned egress_shard_groups.
func NewKernelGroupStore(outer *ebpf.Map) *KernelGroupStore {
	return &KernelGroupStore{
		outer:  outer,
		newMap: ebpf.NewMap,
		writeInner: func(inner *ebpf.Map, value *prog.UsidEgressShardGroupValue) error {
			return inner.Put(uint32(0), value)
		},
		swap: func(outer *ebpf.Map, groupID uint32, inner *ebpf.Map) error {
			return outer.Put(groupID, inner)
		},
	}
}

// Load implements GroupStore.
func (k *KernelGroupStore) Load(groupID uint32) (prog.UsidEgressShardGroupValue, bool, error) {
	var value prog.UsidEgressShardGroupValue
	for range snapshotLookupAttempts {
		var inner *ebpf.Map
		err := k.outer.Lookup(groupID, &inner)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return value, false, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			// Replaced and freed between reading its ID and opening it.
			continue
		}
		if err != nil {
			return value, false, fmt.Errorf("look up egress_shard_groups[%d]: %w", groupID, err)
		}
		err = inner.Lookup(uint32(0), &value)
		_ = inner.Close()
		if err != nil {
			return value, false, fmt.Errorf("read egress_shard_groups[%d] snapshot: %w", groupID, err)
		}
		return value, true, nil
	}
	return value, false, fmt.Errorf("read egress_shard_groups[%d]: snapshot replaced %d times while reading",
		groupID, snapshotLookupAttempts)
}

// Publish implements GroupStore.
func (k *KernelGroupStore) Publish(groupID uint32, value prog.UsidEgressShardGroupValue) error {
	spec := GroupSnapshotSpec
	inner, err := k.newMap(&spec)
	if err != nil {
		return fmt.Errorf("create snapshot map: %w", err)
	}
	defer func() { _ = inner.Close() }()
	if err := k.writeInner(inner, &value); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := k.swap(k.outer, groupID, inner); err != nil {
		return fmt.Errorf("swap snapshot into egress_shard_groups[%d]: %w", groupID, err)
	}
	return nil
}
