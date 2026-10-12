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

// VRFTrafficCounters is one direction's traffic for one VRF, summed across
// every CPU: packets and bytes forwarded, and packets dropped after the VRF
// was resolved. Bytes counts the tenant packet alone, its IP header and
// payload, in both directions.
type VRFTrafficCounters struct {
	Packets        uint64
	Bytes          uint64
	DroppedPackets uint64
}

// VRFTrafficEntry is one decoded vrf_traffic_counters row.
type VRFTrafficEntry struct {
	VRFKey

	// Ingress is traffic delivered into the VRF: decapsulated from the fabric,
	// or sent by another attachment on this node.
	Ingress VRFTrafficCounters

	// Egress is traffic leaving the VRF: encapsulated onto the fabric or toward
	// an egress shard, sent out the public uplink, or delivered to another
	// attachment on this node.
	Egress VRFTrafficCounters
}

// CounterTable is the map-operation surface VRFTrafficTable is written
// against. It differs from Table in creating rows only when absent, so
// registering a VRF again never resets the counters the datapath has
// accumulated for it.
type CounterTable interface {
	// Create adds value at key, returning an error matching ebpf.ErrKeyExist
	// when key is already present.
	Create(key, value any) error

	// Delete removes the entry at key, returning an error matching
	// ebpf.ErrKeyNotExist when key is absent.
	Delete(key any) error

	// Iterate returns an Iterator over every entry, in unspecified order.
	Iterate() Iterator
}

// KernelCounterTable adapts a loaded per-CPU hash map to CounterTable.
type KernelCounterTable struct {
	Map *ebpf.Map
}

// Create adds value at key with BPF_NOEXIST.
func (k KernelCounterTable) Create(key, value any) error {
	return k.Map.Update(key, value, ebpf.UpdateNoExist)
}

// Delete removes the entry at key.
func (k KernelCounterTable) Delete(key any) error { return k.Map.Delete(key) }

// Iterate returns an iterator over every entry.
func (k KernelCounterTable) Iterate() Iterator { return k.Map.Iterate() }

// VRFTrafficTable is the read/write API for vrf_traffic_counters, the
// datapath's per-CPU, per-direction traffic counters for each vrf_table row.
// Its rows are created and removed alongside vrf_table's; VRFTable does so
// itself once given one with WithTraffic.
type VRFTrafficTable struct {
	table CounterTable
	cpus  func() (int, error)
}

// NewVRFTrafficTable wraps table as a VRFTrafficTable. Production callers pass
// a KernelCounterTable over the loaded map; tests pass a fake.
func NewVRFTrafficTable(table CounterTable) *VRFTrafficTable {
	return &VRFTrafficTable{table: table, cpus: ebpf.PossibleCPU}
}

// Ensure creates the zeroed row for (block, argument) if it is absent. An
// existing row, and the counts it holds, is left alone.
func (t *VRFTrafficTable) Ensure(block uint64, argument uint16) error {
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return fmt.Errorf("usidmap: vrf_traffic_counters: ensure block=%#x argument=%#x: %w", block, argument, err)
	}
	return t.ensure(uint64(key))
}

func (t *VRFTrafficTable) ensure(rawKey uint64) error {
	n, err := t.cpus()
	if err != nil {
		return fmt.Errorf("usidmap: vrf_traffic_counters: ensure key=%#x: count possible CPUs: %w", rawKey, err)
	}
	if err := t.table.Create(rawKey, make([]prog.UsidVrfTrafficValue, n)); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return nil
		}
		return fmt.Errorf("usidmap: vrf_traffic_counters: ensure key=%#x: %w", rawKey, err)
	}
	return nil
}

// Remove deletes the row for (block, argument). An already-absent row is not
// an error.
func (t *VRFTrafficTable) Remove(block uint64, argument uint16) error {
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		return fmt.Errorf("usidmap: vrf_traffic_counters: remove block=%#x argument=%#x: %w", block, argument, err)
	}
	return t.remove(uint64(key))
}

func (t *VRFTrafficTable) remove(rawKey uint64) error {
	if err := t.table.Delete(rawKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("usidmap: vrf_traffic_counters: remove key=%#x: %w", rawKey, err)
	}
	return nil
}

// List returns every row, each direction's counters summed across CPUs, in
// unspecified order.
func (t *VRFTrafficTable) List() ([]VRFTrafficEntry, error) {
	var (
		entries []VRFTrafficEntry
		rawKey  uint64
		perCPU  []prog.UsidVrfTrafficValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &perCPU) {
		e := VRFTrafficEntry{VRFKey: decodeVRFKey(rawKey)}
		for _, v := range perCPU {
			e.Ingress.add(v.Ingress)
			e.Egress.add(v.Egress)
		}
		entries = append(entries, e)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("usidmap: vrf_traffic_counters: list: %w", err)
	}
	return entries, nil
}

// Sync makes the table's rows match want, the keys of every vrf_table row:
// it creates a zeroed row for each key missing one and removes every row
// whose key is absent from want and for which stillWanted, consulted just
// before the delete, reports false. stillWanted is consulted again after the
// delete, and a row it now wants is created again, so a VRF registered while
// Sync runs keeps a row. It returns how
// many rows it created and removed; every change is attempted, with the
// errors joined.
func (t *VRFTrafficTable) Sync(
	want map[VRFKey]struct{}, stillWanted func(VRFKey) (bool, error),
) (created, removed int, err error) {
	entries, err := t.List()
	if err != nil {
		return 0, 0, fmt.Errorf("usidmap: vrf_traffic_counters: sync: %w", err)
	}

	var errs []error
	have := make(map[VRFKey]struct{}, len(entries))
	for _, e := range entries {
		have[e.VRFKey] = struct{}{}
		if _, ok := want[e.VRFKey]; ok {
			continue
		}
		keep, err := stillWanted(e.VRFKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("usidmap: vrf_traffic_counters: sync: %w", err))
			continue
		}
		if keep {
			continue
		}
		if err := t.Remove(e.Block, e.Argument); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
		// A registration landing between the check and the delete has already
		// found its row present, so it is put back here.
		if keep, err := stillWanted(e.VRFKey); err != nil {
			errs = append(errs, fmt.Errorf("usidmap: vrf_traffic_counters: sync: %w", err))
		} else if keep {
			if err := t.Ensure(e.Block, e.Argument); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for k := range want {
		if _, ok := have[k]; ok {
			continue
		}
		if err := t.Ensure(k.Block, k.Argument); err != nil {
			errs = append(errs, err)
			continue
		}
		created++
	}
	return created, removed, errors.Join(errs...)
}

func (c *VRFTrafficCounters) add(v prog.UsidVrfDirectionCounter) {
	c.Packets += v.Packets
	c.Bytes += v.Bytes
	c.DroppedPackets += v.DroppedPackets
}

// decodeVRFKey splits a raw vrf_table-style key back into Block and Argument.
func decodeVRFKey(rawKey uint64) VRFKey {
	return VRFKey{
		Block:    rawKey >> uformat.ArgumentBits,
		Argument: uint16(rawKey & (1<<uformat.ArgumentBits - 1)),
	}
}
