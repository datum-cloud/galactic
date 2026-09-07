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

// VRFKey identifies one vrf_table row: the uSID Block that matched in
// locator_table plus the 12-bit Argument. Block is part of the key rather than
// Argument alone, so two Blocks can each hold an independently counted entry
// for the same Argument during a make-before-break migration.
type VRFKey struct {
	Block    uint64
	Argument uint16
}

// VRFEntry is one decoded vrf_table row, kept separate from the generated
// kernel layout so callers outside this package need not import it.
type VRFEntry struct {
	VRFKey

	// VRFTableID is the Linux VRF routing table id
	// (internal/plumbing/vrf.TableID()) this Argument resolves to.
	VRFTableID uint32

	// EgressKind is EgressKindVeth or EgressKindTap: which redirect helper the
	// datapath uses for this entry's resolved egress interface.
	EgressKind uint32

	// Generation is the table's monotonic-clock reading when this entry was
	// last written by Register. See the package doc comment for how Reconcile
	// uses it.
	Generation uint64

	// Packets, Bytes, LastSeenNs, and DroppedPackets are the datapath's own
	// per-Argument counters, updated on every packet matching this entry.
	// Register carries them forward on a re-registration rather than resetting
	// them; they only ever originate from a datapath write and are read back
	// here.
	Packets        uint64
	Bytes          uint64
	LastSeenNs     uint64
	DroppedPackets uint64
}

// VRFTable is the read/write API for vrf_table.
type VRFTable struct {
	table Table
	clock func() uint64
}

// NewVRFTable wraps table as a VRFTable. Production callers pass a kernel table
// over the loaded map, or use NewRegistryFromObjects for all three at once;
// tests pass a fake.
func NewVRFTable(table Table) *VRFTable {
	return &VRFTable{table: table, clock: clockFn}
}

// Generation returns a snapshot of this table's monotonic clock. A caller must
// read it immediately before listing CRDs to build Reconcile's live set, and
// pass the result as that call's cutoff. See the package doc comment for why the
// ordering matters.
func (t *VRFTable) Generation() uint64 {
	return t.clock()
}

// Register writes, or overwrites, the vrf_table entry for (block, argument),
// mapping it to vrfTableID with egressKind and stamping it with this table's
// current generation.
//
// argument 0 is rejected: that value is reserved and the datapath must always
// miss vrf_table for it, so rejecting it here stops an upstream allocator bug
// from planting a live entry for the one value that must never match.
//
// Re-registering an existing key updates its table ID and egress kind and bumps
// the generation, but carries the accumulated counters forward through a
// read-modify-write. A repeat Register of the same key is not always a fresh
// attachment: in the ordinary case it is the CNI ADD retry path re-registering
// after a transient API failure, on an Argument that may already be carrying
// live traffic. A make-before-break migration reads those counters to prove an
// Argument carried none before cutover, and a blind overwrite would make a
// previously live Argument read as untouched. A genuinely new key starts every
// counter at zero, there being nothing to carry forward.
func (t *VRFTable) Register(block uint64, argument uint16, vrfTableID uint32, egressKind uint32) error {
	if err := uformat.ValidateArgument(argument); err != nil {
		return fmt.Errorf("usidmap: vrf_table: register block=%#x argument=%#x: %w", block, argument, err)
	}
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return fmt.Errorf("usidmap: vrf_table: register block=%#x argument=%#x: %w", block, argument, err)
	}

	var existing prog.UsidVrfValue
	if err := t.table.Lookup(uint64(key), &existing); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("usidmap: vrf_table: register block=%#x argument=%#x: look up existing entry: %w",
			block, argument, err)
	}

	value := prog.UsidVrfValue{
		VrfTableId:     vrfTableID,
		EgressKind:     egressKind,
		Generation:     t.clock(),
		Packets:        existing.Packets,
		Bytes:          existing.Bytes,
		LastSeenNs:     existing.LastSeenNs,
		DroppedPackets: existing.DroppedPackets,
	}
	if err := t.table.Put(uint64(key), value); err != nil {
		return fmt.Errorf("usidmap: vrf_table: register block=%#x argument=%#x: %w", block, argument, err)
	}
	return nil
}

// Unregister removes the vrf_table entry for (block, argument) if present. An
// already-absent entry is not an error: both the failed-ADD rollback path and
// the GC sweep call this, and either may race the other having already removed
// it.
func (t *VRFTable) Unregister(block uint64, argument uint16) error {
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return fmt.Errorf("usidmap: vrf_table: unregister block=%#x argument=%#x: %w", block, argument, err)
	}
	if err := t.table.Delete(uint64(key)); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("usidmap: vrf_table: unregister block=%#x argument=%#x: %w", block, argument, err)
	}
	return nil
}

// Get reads the vrf_table entry for (block, argument), reporting whether
// it exists.
func (t *VRFTable) Get(block uint64, argument uint16) (VRFEntry, bool, error) {
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return VRFEntry{}, false, fmt.Errorf("usidmap: vrf_table: get block=%#x argument=%#x: %w", block, argument, err)
	}

	var value prog.UsidVrfValue
	if err := t.table.Lookup(uint64(key), &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return VRFEntry{}, false, nil
		}
		return VRFEntry{}, false, fmt.Errorf("usidmap: vrf_table: get block=%#x argument=%#x: %w", block, argument, err)
	}
	return VRFEntry{
		VRFKey:         VRFKey{Block: block, Argument: argument},
		VRFTableID:     value.VrfTableId,
		EgressKind:     value.EgressKind,
		Generation:     value.Generation,
		Packets:        value.Packets,
		Bytes:          value.Bytes,
		LastSeenNs:     value.LastSeenNs,
		DroppedPackets: value.DroppedPackets,
	}, true, nil
}

// List returns every entry in vrf_table, in unspecified order. The raw key folds
// Block and Argument together, so List decodes both back out of it rather than
// taking a Block parameter the way the single-entry methods do.
func (t *VRFTable) List() ([]VRFEntry, error) {
	var (
		entries []VRFEntry
		rawKey  uint64
		value   prog.UsidVrfValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		entries = append(entries, VRFEntry{
			VRFKey: VRFKey{
				Block:    rawKey >> uformat.ArgumentBits,
				Argument: uint16(rawKey & (1<<uformat.ArgumentBits - 1)),
			},
			VRFTableID:     value.VrfTableId,
			EgressKind:     value.EgressKind,
			Generation:     value.Generation,
			Packets:        value.Packets,
			Bytes:          value.Bytes,
			LastSeenNs:     value.LastSeenNs,
			DroppedPackets: value.DroppedPackets,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("usidmap: vrf_table: list: %w", err)
	}
	return entries, nil
}

// Reconcile brings vrf_table into agreement with live, the caller's current set
// of (Block, Argument) pairs backed by a live BGPVRFInstance CRD. It removes
// every entry whose key is absent from live, except one whose generation is at
// or above cutoff, and returns the entries removed.
//
// cutoff must come from this table's Generation, read before the caller listed
// CRDs. An entry at or above it was registered at or after that snapshot, so it
// is kept whatever live says and re-evaluated on the next call, once the CRD
// list has caught up. Only older entries whose key is genuinely absent are
// candidates for deletion.
//
// Every stale candidate is attempted even if deleting one fails, with the errors
// joined; removed lists everything actually deleted regardless.
func (t *VRFTable) Reconcile(live map[VRFKey]struct{}, cutoff uint64) (removed []VRFEntry, err error) {
	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("usidmap: vrf_table: reconcile: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if _, ok := live[e.VRFKey]; ok {
			continue // still has a live BGPVRFInstance per the CRD snapshot
		}
		if e.Generation >= cutoff {
			// Registered at or after the CRD snapshot, so too new to judge
			// against a live set captured before it existed. Leave it for the
			// next sweep.
			continue
		}
		if err := t.Unregister(e.Block, e.Argument); err != nil {
			errs = append(errs, fmt.Errorf("usidmap: vrf_table: reconcile: delete stale entry %+v: %w", e.VRFKey, err))
			continue
		}
		removed = append(removed, e)
	}
	return removed, errors.Join(errs...)
}
