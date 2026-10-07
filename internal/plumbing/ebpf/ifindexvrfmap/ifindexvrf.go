// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// SidecarIfindexBase splits the interface index space of ifindex_vrf_table
// between its two writers. The ingress sidecar creates every interface it
// registers with an explicit index of SidecarIfindexBase plus that VRF's uSID
// Argument, and the host registers only indexes below it.
//
// Each network namespace numbers its interfaces on its own, from 1 upward,
// but the sidecar registers indexes from its pod's namespace into the same
// pinned map the host CNI writes host indexes into. Without disjoint ranges, a
// sidecar interface and a host interface with the same index overwrite each
// other's row, and usid_egress routes one's traffic into the other's VRF.
//
// A host namespace allocates indexes sequentially and never gets near 2^30.
const SidecarIfindexBase = uint32(0x40000000)

// SidecarIfindex returns the interface index the ingress sidecar gives the
// interface it registers for the VRF whose uSID Argument is argument.
func SidecarIfindex(argument uint16) uint32 {
	return SidecarIfindexBase + uint32(argument)
}

// IfindexVRFEntry is one decoded ifindex_vrf_table row, kept separate from the
// generated kernel layout.
type IfindexVRFEntry struct {
	Ifindex uint32
	Block   uint64

	// Argument is the 12-bit uSID Argument this ifindex's VRF resolves to.
	Argument uint16

	// Generation is this process's in-memory record of when this entry was last
	// registered. See the package doc comment for why it is not
	// kernel-persisted.
	Generation uint64
}

// IfindexVRFTable is the read/write API for ifindex_vrf_table.
type IfindexVRFTable struct {
	table usidmap.Table
	clock func() uint64

	mu         sync.Mutex
	generation map[uint32]uint64
}

// NewIfindexVRFTable wraps table as an IfindexVRFTable. Production callers pass
// a kernel table over the loaded map, or use OpenPinned; tests pass a fake.
func NewIfindexVRFTable(table usidmap.Table) *IfindexVRFTable {
	return &IfindexVRFTable{table: table, clock: monotonicNow, generation: make(map[uint32]uint64)}
}

// OpenPinned opens ifindex_vrf_table from its pinned path under pinDir and
// returns a table wrapping it, for a process that did not itself load the
// datapath but needs to read or write this one map. The returned map is also the
// table's closer and must be closed when the caller is done, which does not
// affect its pinned lifetime.
func OpenPinned(pinDir string) (*IfindexVRFTable, *ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapIfindexVrfTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ifindexvrfmap: open pinned map %q: %w", prog.UsidMapIfindexVrfTable, err)
	}
	return NewIfindexVRFTable(usidmap.KernelTable{Map: m}), m, nil
}

// Generation returns a snapshot of this table's monotonic clock.
func (t *IfindexVRFTable) Generation() uint64 {
	return t.clock()
}

// Register writes, or overwrites, the ifindex_vrf_table entry for ifindex,
// mapping it to (block, argument). It carries no counters, so every call is a
// plain overwrite with no read-modify-write step.
func (t *IfindexVRFTable) Register(ifindex uint32, block uint64, argument uint16) error {
	if err := uformat.ValidateBlock(block); err != nil {
		return fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: register ifindex=%d: %w", ifindex, err)
	}
	if err := uformat.ValidateArgument(argument); err != nil {
		return fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: register ifindex=%d: %w", ifindex, err)
	}
	if err := validateIfindexOwner(ifindex, block, argument); err != nil {
		return fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: register ifindex=%d: %w", ifindex, err)
	}

	value := prog.UsidIfindexVrfValue{Block: block, Argument: argument}
	if err := t.table.Put(ifindex, value); err != nil {
		return fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: register ifindex=%d: %w", ifindex, err)
	}

	t.mu.Lock()
	t.generation[ifindex] = t.clock()
	t.mu.Unlock()
	return nil
}

// validateIfindexOwner rejects a registration that would cross into the other
// writer's index range; see SidecarIfindexBase. The ingress sidecar registers
// only under uformat.BlockIngressSidecar, so the Block identifies the writer.
func validateIfindexOwner(ifindex uint32, block uint64, argument uint16) error {
	if block == uformat.BlockIngressSidecar {
		if want := SidecarIfindex(argument); ifindex != want {
			return fmt.Errorf("ingress sidecar interface for argument %#x must have index %d", argument, want)
		}
		return nil
	}
	if ifindex >= SidecarIfindexBase {
		return fmt.Errorf("host interface index is in the range reserved for the ingress sidecar (>= %d)",
			SidecarIfindexBase)
	}
	return nil
}

// Unregister removes the ifindex_vrf_table entry for ifindex if present. An
// already-absent entry is not an error: DEL is idempotent per the CNI spec, and
// every caller treats cleanup as best-effort.
func (t *IfindexVRFTable) Unregister(ifindex uint32) error {
	if err := t.table.Delete(ifindex); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: unregister ifindex=%d: %w", ifindex, err)
		}
	}
	t.mu.Lock()
	delete(t.generation, ifindex)
	t.mu.Unlock()
	return nil
}

// Get reads the ifindex_vrf_table entry for ifindex, reporting whether it
// exists.
func (t *IfindexVRFTable) Get(ifindex uint32) (IfindexVRFEntry, bool, error) {
	var value prog.UsidIfindexVrfValue
	if err := t.table.Lookup(ifindex, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return IfindexVRFEntry{}, false, nil
		}
		return IfindexVRFEntry{}, false, fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: get ifindex=%d: %w", ifindex, err)
	}
	return t.decode(ifindex, value), true, nil
}

// List returns every entry currently in ifindex_vrf_table, in unspecified
// order.
func (t *IfindexVRFTable) List() ([]IfindexVRFEntry, error) {
	var (
		entries []IfindexVRFEntry
		rawKey  uint32
		value   prog.UsidIfindexVrfValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		entries = append(entries, t.decode(rawKey, value))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: list: %w", err)
	}
	return entries, nil
}

// Reconcile brings ifindex_vrf_table into agreement with live, the caller's
// current set of ifindexes that should have an entry, removing every entry whose
// key is absent except one whose generation is at or above cutoff. See the
// package doc comment for why no production sweep uses it today.
func (t *IfindexVRFTable) Reconcile(live map[uint32]struct{}, cutoff uint64) (removed []IfindexVRFEntry, err error) {
	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: reconcile: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if _, ok := live[e.Ifindex]; ok {
			continue
		}
		if e.Generation >= cutoff {
			continue
		}
		if err := t.Unregister(e.Ifindex); err != nil {
			errs = append(errs, fmt.Errorf("ifindexvrfmap: ifindex_vrf_table: reconcile: delete stale entry %+v: %w",
				e, err))
			continue
		}
		removed = append(removed, e)
	}
	return removed, errors.Join(errs...)
}

func (t *IfindexVRFTable) decode(ifindex uint32, value prog.UsidIfindexVrfValue) IfindexVRFEntry {
	t.mu.Lock()
	gen := t.generation[ifindex]
	t.mu.Unlock()

	return IfindexVRFEntry{
		Ifindex:    ifindex,
		Block:      value.Block,
		Argument:   value.Argument,
		Generation: gen,
	}
}
