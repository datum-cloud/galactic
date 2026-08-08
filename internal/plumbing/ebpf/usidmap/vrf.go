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
// locator_table, plus the 12-bit Argument. Block is part of the key, not
// Argument alone (design plan R8), so two Blocks can each hold an
// independently counted, independently matched entry for the same Argument
// value during a make-before-break migration.
type VRFKey struct {
	Block    uint64
	Argument uint16
}

// VRFEntry is one fully decoded vrf_table row, decoupled from
// prog.UsidVrfValue's cilium/ebpf/BTF-generated field layout so callers
// outside this package (the GC controller, Milestone 7.3; the CNI
// registration call, Milestone 7.1) don't need to import prog or
// cilium/ebpf directly.
type VRFEntry struct {
	VRFKey

	// VRFTableID is the Linux VRF routing table id
	// (internal/plumbing/vrf.TableID()) this Argument resolves to.
	VRFTableID uint32

	// EgressKind is EgressKindVeth or EgressKindTap -- which redirect
	// helper usid_ingress's step 9 uses for this entry's resolved egress
	// interface (Milestone 6.1's tap-mode redirect fix).
	EgressKind uint32

	// Generation is the table's monotonic-clock reading (table.go's
	// monotonicNow) at the time this entry was last written by Register.
	// See doc.go's "plugin-binary-vs-run-container race" section for how
	// Reconcile uses it.
	Generation uint64

	// Packets, Bytes, LastSeenNs, and DroppedPackets are the datapath's own
	// per-Argument hit counters (design plan R8), updated by usid_ingress
	// itself on every packet that matches this entry. Register carries
	// these forward on a re-registration of an existing key rather than
	// resetting them (see Register's doc comment) -- they only ever
	// originate from a real map write by the datapath itself, and are read
	// back here via Get/List/Reconcile.
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

// NewVRFTable wraps table as a VRFTable. Production callers pass a
// KernelTable wrapping a loaded *prog.UsidObjects's VrfTable map (or use
// NewRegistryFromObjects, which does this for all three tables at once);
// tests pass a fake Table.
func NewVRFTable(table Table) *VRFTable {
	return &VRFTable{table: table, clock: clockFn}
}

// Generation returns a snapshot of this table's monotonic clock. The GC
// controller (Milestone 7.3) must call this immediately *before* listing
// BGPVRFInstance CRDs for Reconcile's live set, and pass the result as
// Reconcile's cutoff argument -- see doc.go's "plugin-binary-vs-run-
// container race" section for why the ordering matters.
func (t *VRFTable) Generation() uint64 {
	return t.clock()
}

// Register writes (or overwrites) the vrf_table entry for (block,
// argument), mapping it to vrfTableID and stamping it with this table's
// current Generation (design plan §5.1, §5.4).
//
// Register rejects argument == 0 outright: PR #740 reserves Instance ID
// 0x000, and the datapath is required to always miss vrf_table for it
// (R4) -- rejecting it here means a caller bug upstream of Register
// (whatever eventually allocates Arguments, out of this plan's scope)
// cannot silently plant a live entry for the one value that must always
// miss.
//
// Re-registering an existing (block, argument) key updates its
// VRFTableID/EgressKind and bumps Generation, but preserves whatever
// Packets/Bytes/LastSeenNs usid_ingress has already accumulated against it
// (a read-modify-write: Register looks the key up first, and carries its
// existing counter fields forward into the value it writes). This matters
// because a repeat Register of the *same* key is not always a fresh
// attachment lifecycle -- it is also, in the ordinary case, the CNI ADD
// retry path re-registering after a transient k8s-op failure
// (internal/cnibgp/bgp.go's retryK8sOps), which happens on an Argument that
// may already be carrying live traffic. R8's make-before-break migration
// gate reads these counters to prove an Argument carried no traffic before
// cutover; a blind overwrite that zeroed them on every retry would make a
// previously-live Argument read as untouched. A genuinely new key (no
// prior entry) still starts every counter at zero, since there is nothing
// to carry forward -- ebpf.ErrKeyNotExist from the Lookup below is exactly
// that case, not a failure.
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

// Unregister removes the vrf_table entry for (block, argument), if
// present. It is not an error to unregister an already-absent entry --
// design plan §5.1 requires this call at both the failed-ADD rollback path
// (Milestone 7.2) and the GC sweep (Milestone 7.3), and either caller may
// legitimately race with the other having already removed the same entry.
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

// List returns every entry currently in vrf_table, in unspecified order.
// Because vrf_table's key (Block<<12|Argument, see uformat.NewVRFKey)
// folds Block and Argument together, List decodes both back out of each
// raw key rather than needing a separate Block parameter the way
// Get/Register/Unregister do.
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

// Reconcile brings vrf_table into agreement with live -- the caller's
// current set of (Block, Argument) pairs that have a live BGPVRFInstance
// CRD -- removing every vrf_table entry whose key is absent from live,
// *except* an entry whose Generation is >= cutoff.
//
// cutoff must be a value returned by this table's own Generation, captured
// by the caller *before* it lists CRDs to build live (see doc.go's
// "plugin-binary-vs-run-container race" section, and Generation's own doc
// comment). An entry with Generation >= cutoff was registered at or after
// that snapshot was taken, so it is always kept here regardless of whether
// its key is in live -- it is correctly re-evaluated on the caller's
// *next* Reconcile call, once the CRD list has had a chance to catch up.
// Only entries older than the snapshot (Generation < cutoff) are ever
// candidates for deletion, and then only if their key is genuinely absent
// from live.
//
// Reconcile attempts every stale candidate even if deleting one fails,
// joining every such error into the returned error with errors.Join;
// removed lists every entry actually deleted, regardless of whether a
// later deletion in the same call failed.
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
			// Registered at or after the CRD-list snapshot was taken --
			// too new to judge against a live set captured before it
			// existed. Leave it for the next sweep (design plan §5.4).
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
