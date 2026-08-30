// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package markvrfmap

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

// MarkVRFEntry is one fully decoded mark_vrf_table row, decoupled from
// prog.UsidMarkVrfValue's cilium/ebpf/BTF-generated field layout --
// mirrors ifindexvrfmap.IfindexVRFEntry's own reasoning.
type MarkVRFEntry struct {
	Mark  uint32
	Block uint64

	// Argument is the 12-bit uSID Argument this mark's VRF resolves to.
	Argument uint16

	// Generation is this process's own in-memory bookkeeping of when this
	// entry was last (re-)registered -- see doc.go for why this is not
	// kernel-persisted.
	Generation uint64
}

// MarkVRFTable is the read/write API for mark_vrf_table.
type MarkVRFTable struct {
	table usidmap.Table
	clock func() uint64

	mu         sync.Mutex
	generation map[uint32]uint64
}

// NewMarkVRFTable wraps table as a MarkVRFTable. Production callers pass a
// usidmap.KernelTable wrapping a loaded *prog.UsidObjects's MarkVrfTable map
// (or OpenPinned, below); tests pass a fake usidmap.Table.
func NewMarkVRFTable(table usidmap.Table) *MarkVRFTable {
	return &MarkVRFTable{table: table, clock: monotonicNow, generation: make(map[uint32]uint64)}
}

// OpenPinned opens mark_vrf_table from its pinned path under pinDir and
// returns a MarkVRFTable wrapping it, mirroring ifindexvrfmap.OpenPinned --
// for a process (internal/ingresssidecar's ensureEgressDatapath/
// removeEgressDatapath) that did not itself load the datapath but needs to
// read/write this one map. The returned *ebpf.Map is also this table's own
// io.Closer and must be closed once the caller is done; it does not affect
// the map's pinned lifetime.
func OpenPinned(pinDir string) (*MarkVRFTable, *ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapMarkVrfTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("markvrfmap: open pinned map %q: %w", prog.UsidMapMarkVrfTable, err)
	}
	return NewMarkVRFTable(usidmap.KernelTable{Map: m}), m, nil
}

// Generation returns a snapshot of this table's monotonic clock.
func (t *MarkVRFTable) Generation() uint64 {
	return t.clock()
}

// Register writes (or overwrites) the mark_vrf_table entry for mark,
// mapping it to (block, argument). Like ifindexvrfmap.IfindexVRFTable's own
// Register, this carries no counters and is always a plain overwrite --
// there is no read-modify-write step.
func (t *MarkVRFTable) Register(mark uint32, block uint64, argument uint16) error {
	if err := uformat.ValidateBlock(block); err != nil {
		return fmt.Errorf("markvrfmap: mark_vrf_table: register mark=%d: %w", mark, err)
	}
	if err := uformat.ValidateArgument(argument); err != nil {
		return fmt.Errorf("markvrfmap: mark_vrf_table: register mark=%d: %w", mark, err)
	}

	value := prog.UsidMarkVrfValue{Block: block, Argument: argument}
	if err := t.table.Put(mark, value); err != nil {
		return fmt.Errorf("markvrfmap: mark_vrf_table: register mark=%d: %w", mark, err)
	}

	t.mu.Lock()
	t.generation[mark] = t.clock()
	t.mu.Unlock()
	return nil
}

// Unregister removes the mark_vrf_table entry for mark, if present. Not an
// error to unregister an already-absent entry -- every caller of this
// (internal/ingresssidecar's removeEgressDatapath) treats every cleanup
// step as best-effort.
func (t *MarkVRFTable) Unregister(mark uint32) error {
	if err := t.table.Delete(mark); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("markvrfmap: mark_vrf_table: unregister mark=%d: %w", mark, err)
		}
	}
	t.mu.Lock()
	delete(t.generation, mark)
	t.mu.Unlock()
	return nil
}

// Get reads the mark_vrf_table entry for mark, reporting whether it exists.
func (t *MarkVRFTable) Get(mark uint32) (MarkVRFEntry, bool, error) {
	var value prog.UsidMarkVrfValue
	if err := t.table.Lookup(mark, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return MarkVRFEntry{}, false, nil
		}
		return MarkVRFEntry{}, false, fmt.Errorf("markvrfmap: mark_vrf_table: get mark=%d: %w", mark, err)
	}
	return t.decode(mark, value), true, nil
}

// List returns every entry currently in mark_vrf_table, in unspecified
// order.
func (t *MarkVRFTable) List() ([]MarkVRFEntry, error) {
	var (
		entries []MarkVRFEntry
		rawKey  uint32
		value   prog.UsidMarkVrfValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		entries = append(entries, t.decode(rawKey, value))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("markvrfmap: mark_vrf_table: list: %w", err)
	}
	return entries, nil
}

// Reconcile brings mark_vrf_table into agreement with live -- the caller's
// current set of marks that should have an entry -- removing every entry
// whose key is absent from live, except an entry whose Generation is >=
// cutoff. Mirrors ifindexvrfmap.IfindexVRFTable.Reconcile's exact
// semantics; not wired into any production sweep today for the same reason
// that table's own Reconcile isn't -- exists for parity, test coverage, and
// as a future defense-in-depth backstop.
func (t *MarkVRFTable) Reconcile(live map[uint32]struct{}, cutoff uint64) (removed []MarkVRFEntry, err error) {
	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("markvrfmap: mark_vrf_table: reconcile: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if _, ok := live[e.Mark]; ok {
			continue
		}
		if e.Generation >= cutoff {
			continue
		}
		if err := t.Unregister(e.Mark); err != nil {
			errs = append(errs, fmt.Errorf("markvrfmap: mark_vrf_table: reconcile: delete stale entry %+v: %w",
				e, err))
			continue
		}
		removed = append(removed, e)
	}
	return removed, errors.Join(errs...)
}

func (t *MarkVRFTable) decode(mark uint32, value prog.UsidMarkVrfValue) MarkVRFEntry {
	t.mu.Lock()
	gen := t.generation[mark]
	t.mu.Unlock()

	return MarkVRFEntry{
		Mark:       mark,
		Block:      value.Block,
		Argument:   value.Argument,
		Generation: gen,
	}
}
