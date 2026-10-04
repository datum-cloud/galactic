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

// VPCAttributionEntry is one decoded vpc_attribution_table row: the
// VPC/VPCAttachment identity registerEBPFDatapath already knows for a
// (Block, Argument) at CNI ADD time, kept alongside vrf_table's own counters
// so byte accounting (datum-cloud/enhancements#878) can attribute them to a
// tenant without a central uSID-to-VPC lookup for the receiving side, which
// this node already knows about its own local attachments.
type VPCAttributionEntry struct {
	VRFKey

	// VPC and VPCAttachment are the decoded numeric form of the base62
	// identifiers CNI configuration carries (48-bit VPC, 16-bit
	// VPCAttachment; see docs/cni/conflist-reference.md).
	VPC           uint64
	VPCAttachment uint32

	// Generation is this table's monotonic-clock reading when this entry was
	// last written by Register. See VRFTable's own doc comment for how
	// Reconcile uses it; the two tables share the same convention.
	Generation uint64
}

// VPCAttributionTable is the read/write API for vpc_attribution_table.
// Wholly independent of vrf_table's own schema: usid_ingress and
// usid_egress never read this map, so a change here can never affect a live
// packet's verdict, and vice versa.
type VPCAttributionTable struct {
	table Table
	clock func() uint64
}

// NewVPCAttributionTable wraps table as a VPCAttributionTable. Production
// callers pass a kernel table over the loaded map, or use
// NewRegistryFromObjects/OpenPinnedRegistry for every table at once; tests
// pass a fake.
func NewVPCAttributionTable(table Table) *VPCAttributionTable {
	return &VPCAttributionTable{table: table, clock: clockFn}
}

// Generation returns a snapshot of this table's monotonic clock, for the same
// Reconcile cutoff use as VRFTable.Generation.
func (t *VPCAttributionTable) Generation() uint64 {
	return t.clock()
}

// Register writes, or overwrites, the vpc_attribution_table entry for
// (block, argument), mapping it to (vpc, vpcAttachment) and stamping it with
// this table's current generation. Callers register this alongside
// registry.VRF.Register, keyed identically.
func (t *VPCAttributionTable) Register(block uint64, argument uint16, vpc uint64, vpcAttachment uint32) error {
	if err := uformat.ValidateArgument(argument); err != nil {
		return fmt.Errorf("usidmap: vpc_attribution_table: register block=%#x argument=%#x: %w", block, argument, err)
	}
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return fmt.Errorf("usidmap: vpc_attribution_table: register block=%#x argument=%#x: %w", block, argument, err)
	}

	value := prog.UsidVpcAttributionValue{
		Vpc:           vpc,
		VpcAttachment: vpcAttachment,
		Generation:    t.clock(),
	}
	if err := t.table.Put(uint64(key), value); err != nil {
		return fmt.Errorf("usidmap: vpc_attribution_table: register block=%#x argument=%#x: %w", block, argument, err)
	}
	return nil
}

// Unregister removes the vpc_attribution_table entry for (block, argument) if
// present. An already-absent entry is not an error, matching
// VRFTable.Unregister's own rollback/GC-race tolerance.
func (t *VPCAttributionTable) Unregister(block uint64, argument uint16) error {
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return fmt.Errorf("usidmap: vpc_attribution_table: unregister block=%#x argument=%#x: %w", block, argument, err)
	}
	if err := t.table.Delete(uint64(key)); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("usidmap: vpc_attribution_table: unregister block=%#x argument=%#x: %w", block, argument, err)
	}
	return nil
}

// Get reads the vpc_attribution_table entry for (block, argument), reporting
// whether it exists.
func (t *VPCAttributionTable) Get(block uint64, argument uint16) (VPCAttributionEntry, bool, error) {
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return VPCAttributionEntry{}, false,
			fmt.Errorf("usidmap: vpc_attribution_table: get block=%#x argument=%#x: %w", block, argument, err)
	}

	var value prog.UsidVpcAttributionValue
	if err := t.table.Lookup(uint64(key), &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return VPCAttributionEntry{}, false, nil
		}
		return VPCAttributionEntry{}, false,
			fmt.Errorf("usidmap: vpc_attribution_table: get block=%#x argument=%#x: %w", block, argument, err)
	}
	return VPCAttributionEntry{
		VRFKey:        VRFKey{Block: block, Argument: argument},
		VPC:           value.Vpc,
		VPCAttachment: value.VpcAttachment,
		Generation:    value.Generation,
	}, true, nil
}

// List returns every entry in vpc_attribution_table, in unspecified order.
func (t *VPCAttributionTable) List() ([]VPCAttributionEntry, error) {
	var (
		entries []VPCAttributionEntry
		rawKey  uint64
		value   prog.UsidVpcAttributionValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		entries = append(entries, VPCAttributionEntry{
			VRFKey: VRFKey{
				Block:    rawKey >> uformat.ArgumentBits,
				Argument: uint16(rawKey & (1<<uformat.ArgumentBits - 1)),
			},
			VPC:           value.Vpc,
			VPCAttachment: value.VpcAttachment,
			Generation:    value.Generation,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("usidmap: vpc_attribution_table: list: %w", err)
	}
	return entries, nil
}

// Reconcile brings vpc_attribution_table into agreement with live, the same
// (Block, Argument) live set and cutoff generation VRFTable.Reconcile is
// called with — the two tables share the same key and lifecycle, so a
// caller reconciles them together. See VRFTable.Reconcile's own doc comment
// for the cutoff-ordering requirement.
func (t *VPCAttributionTable) Reconcile(
	live map[VRFKey]struct{}, cutoff uint64,
) (removed []VPCAttributionEntry, err error) {
	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("usidmap: vpc_attribution_table: reconcile: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if _, ok := live[e.VRFKey]; ok {
			continue
		}
		if e.Generation >= cutoff {
			continue
		}
		if err := t.Unregister(e.Block, e.Argument); err != nil {
			errs = append(errs,
				fmt.Errorf("usidmap: vpc_attribution_table: reconcile: delete stale entry %+v: %w", e.VRFKey, err))
			continue
		}
		removed = append(removed, e)
	}
	return removed, errors.Join(errs...)
}
