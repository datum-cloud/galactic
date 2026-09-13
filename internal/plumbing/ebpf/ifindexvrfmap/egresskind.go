// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// EgressKindTable is the read/write API for ifindex_egress_kind_table: which
// redirect helper usid_ingress uses to deliver into one attachment's host-side
// interface, keyed by that interface's ifindex.
//
// It is per interface rather than a field of vrf_table's per-VPC entry because
// one VPC can hold both tap and veth attachments on the same node. It shares
// ifindex_vrf_table's lifecycle, written at CNI ADD and removed at DEL, so it
// needs no generation bookkeeping of its own.
type EgressKindTable struct {
	table usidmap.Table
}

// NewEgressKindTable wraps table as an EgressKindTable. Production callers use
// OpenPinnedEgressKind; tests pass a fake.
func NewEgressKindTable(table usidmap.Table) *EgressKindTable {
	return &EgressKindTable{table: table}
}

// OpenPinnedEgressKind opens ifindex_egress_kind_table from its pinned path
// under pinDir. The returned map must be closed when the caller is done.
//
// The error wraps os.ErrNotExist when the running datapath predates this map.
// The CNI binary is installed before the datapath that pins the map is
// reloaded, so callers must be able to tell that window apart from a real
// failure.
func OpenPinnedEgressKind(pinDir string) (*EgressKindTable, *ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapIfindexEgressKindTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ifindexvrfmap: open pinned map %q: %w", prog.UsidMapIfindexEgressKindTable, err)
	}
	return NewEgressKindTable(usidmap.KernelTable{Map: m}), m, nil
}

// Register writes, or overwrites, the egress kind for ifindex. An unknown kind
// is rejected rather than written, since the datapath treats every value other
// than usidmap.EgressKindVeth as a plain redirect and would hide the mistake.
func (t *EgressKindTable) Register(ifindex uint32, egressKind uint32) error {
	if egressKind != usidmap.EgressKindVeth && egressKind != usidmap.EgressKindTap {
		return fmt.Errorf("ifindexvrfmap: ifindex_egress_kind_table: register ifindex=%d: unknown egress kind %d",
			ifindex, egressKind)
	}
	if err := t.table.Put(ifindex, egressKind); err != nil {
		return fmt.Errorf("ifindexvrfmap: ifindex_egress_kind_table: register ifindex=%d: %w", ifindex, err)
	}
	return nil
}

// Unregister removes the entry for ifindex if present. An already-absent entry
// is not an error: DEL is idempotent per the CNI spec.
func (t *EgressKindTable) Unregister(ifindex uint32) error {
	if err := t.table.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("ifindexvrfmap: ifindex_egress_kind_table: unregister ifindex=%d: %w", ifindex, err)
	}
	return nil
}

// Get reads the egress kind for ifindex, reporting whether an entry exists.
func (t *EgressKindTable) Get(ifindex uint32) (egressKind uint32, ok bool, err error) {
	if err := t.table.Lookup(ifindex, &egressKind); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("ifindexvrfmap: ifindex_egress_kind_table: get ifindex=%d: %w", ifindex, err)
	}
	return egressKind, true, nil
}
