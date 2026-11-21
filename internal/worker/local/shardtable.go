// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"sync"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// PinnedShards is LocalShards over galactic-cni's pinned egress_local_shard.
// It opens the pin on first use, and again after a failure, so a Worker
// that starts before galactic-cni has loaded the uSID datapath picks it up
// later. While the pin is missing every call fails with an error matching
// os.ErrNotExist, which Local reports as DatapathNotLoaded.
type PinnedShards struct {
	PinDir string

	mu sync.Mutex
	t  *egressroutemap.LocalShardTable
}

func (p *PinnedShards) table() (*egressroutemap.LocalShardTable, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.t == nil {
		t, err := egressroutemap.OpenPinnedLocalShardTable(p.PinDir)
		if err != nil {
			return nil, err
		}
		p.t = t
	}
	return p.t, nil
}

// Put implements LocalShards.
func (p *PinnedShards) Put(tableID uint32, row LocalShardRow) error {
	t, err := p.table()
	if err != nil {
		return err
	}
	return t.Put(tableID, egressroutemap.LocalShard{ShardSID: row.ShardSID, PairIfindex: row.PairIfindex})
}

// Delete implements LocalShards.
func (p *PinnedShards) Delete(tableID uint32) error {
	t, err := p.table()
	if err != nil {
		return err
	}
	return t.Delete(tableID)
}

// Get implements LocalShards.
func (p *PinnedShards) Get(tableID uint32) (LocalShardRow, bool, error) {
	t, err := p.table()
	if err != nil {
		return LocalShardRow{}, false, err
	}
	s, ok, err := t.Get(tableID)
	return LocalShardRow{ShardSID: s.ShardSID, PairIfindex: s.PairIfindex}, ok, err
}

// All implements LocalShards.
func (p *PinnedShards) All() (map[uint32]LocalShardRow, error) {
	t, err := p.table()
	if err != nil {
		return nil, err
	}
	all, err := t.All()
	if err != nil {
		return nil, err
	}
	out := make(map[uint32]LocalShardRow, len(all))
	for k, s := range all {
		out[k] = LocalShardRow{ShardSID: s.ShardSID, PairIfindex: s.PairIfindex}
	}
	return out, nil
}

// Close releases the map descriptor; the pin stays.
func (p *PinnedShards) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.t == nil {
		return nil
	}
	err := p.t.Close()
	p.t = nil
	return err
}
