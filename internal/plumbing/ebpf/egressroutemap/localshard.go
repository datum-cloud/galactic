// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// LocalShard is one egress_local_shard row: the VPC whose VRF table keys it
// has a ready service-internal veth pair into this node's own NAT shard.
type LocalShard struct {
	// ShardSID is the local shard's base SID.
	ShardSID netip.Addr
	// PairIfindex is the ifindex of the pair's tenant end.
	PairIfindex uint32
}

// LocalShardTable reads and writes egress_local_shard. Galactic Worker is its
// only writer; usid_egress reads it to choose a group's local view, and the
// egress sweep reads it to place ordered-mode class routes.
type LocalShardTable struct {
	m *ebpf.Map
}

// NewLocalShardTable wraps a loaded or pinned egress_local_shard.
func NewLocalShardTable(m *ebpf.Map) *LocalShardTable {
	return &LocalShardTable{m: m}
}

// OpenPinnedLocalShardTable opens egress_local_shard from its pin under
// pinDir. A datapath older than the map has no such pin, and the error then
// matches os.ErrNotExist.
func OpenPinnedLocalShardTable(pinDir string) (*LocalShardTable, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapEgressLocalShard), nil)
	if err != nil {
		return nil, fmt.Errorf("egressroutemap: open pinned map %q under %q: %w",
			prog.UsidMapEgressLocalShard, pinDir, err)
	}
	return NewLocalShardTable(m), nil
}

// Put writes tableID's row.
func (t *LocalShardTable) Put(tableID uint32, s LocalShard) error {
	if !s.ShardSID.Is6() || s.ShardSID.Is4In6() {
		return fmt.Errorf("egressroutemap: egress_local_shard: shard SID %s is not IPv6", s.ShardSID)
	}
	value := prog.UsidEgressLocalShardValue{ShardSid: s.ShardSID.As16(), PairIfindex: s.PairIfindex}
	if err := t.m.Put(tableID, value); err != nil {
		return fmt.Errorf("egressroutemap: egress_local_shard: put table=%d: %w", tableID, err)
	}
	return nil
}

// Delete removes tableID's row. A missing row is not an error.
func (t *LocalShardTable) Delete(tableID uint32) error {
	if err := t.m.Delete(tableID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("egressroutemap: egress_local_shard: delete table=%d: %w", tableID, err)
	}
	return nil
}

// Get returns tableID's row, and false when it has none.
func (t *LocalShardTable) Get(tableID uint32) (LocalShard, bool, error) {
	var value prog.UsidEgressLocalShardValue
	if err := t.m.Lookup(tableID, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return LocalShard{}, false, nil
		}
		return LocalShard{}, false, fmt.Errorf("egressroutemap: egress_local_shard: get table=%d: %w", tableID, err)
	}
	return localShardOf(value), true, nil
}

// All returns every row by VRF table ID.
func (t *LocalShardTable) All() (map[uint32]LocalShard, error) {
	out := map[uint32]LocalShard{}
	var (
		key   uint32
		value prog.UsidEgressLocalShardValue
	)
	it := t.m.Iterate()
	for it.Next(&key, &value) {
		out[key] = localShardOf(value)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("egressroutemap: egress_local_shard: iterate: %w", err)
	}
	return out, nil
}

// Close releases this process's descriptor. The pin stays.
func (t *LocalShardTable) Close() error {
	return t.m.Close()
}

func localShardOf(v prog.UsidEgressLocalShardValue) LocalShard {
	return LocalShard{ShardSID: netip.AddrFrom16(v.ShardSid), PairIfindex: v.PairIfindex}
}
