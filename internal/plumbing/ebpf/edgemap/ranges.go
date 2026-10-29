// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemap

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

const MaxRangesPerVIP = 16

type RangeTable struct {
	table Table
	clock func() uint64
}

func NewRangeTable(table Table) *RangeTable { return &RangeTable{table: table, clock: clockFn} }

func rangeKey(key VIPKey) (edgeprog.EdgedsrVipKey, error) { key.VPort = 0; return toWireKey(key) }

func (t *RangeTable) Register(key VIPKey, end uint16, generation uint64) error {
	if key.Proto != 17 || key.VPort == 0 || end < key.VPort || !key.VIP.Is6() || key.VIP.Is4In6() {
		return fmt.Errorf("invalid IPv6 UDP range %v-%d", key, end)
	}
	raw, err := rangeKey(key)
	if err != nil {
		return err
	}
	var value edgeprog.EdgedsrVipRangeValue
	if err = t.table.Lookup(raw, &value); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if value.Count > MaxRangesPerVIP {
		return fmt.Errorf("invalid range count %d", value.Count)
	}
	intervals := make([]edgeprog.EdgedsrVipRange, 0, MaxRangesPerVIP)
	for _, r := range value.Ranges[:value.Count] {
		if r.Start == key.VPort {
			continue
		}
		if r.Start <= end && key.VPort <= r.End {
			return fmt.Errorf("range intersects %d-%d", r.Start, r.End)
		}
		intervals = append(intervals, r)
	}
	if len(intervals) == MaxRangesPerVIP {
		return fmt.Errorf("range capacity %d exceeded", MaxRangesPerVIP)
	}
	intervals = append(intervals, edgeprog.EdgedsrVipRange{Start: key.VPort, End: end, Generation: generation})
	slices.SortFunc(intervals, func(a, b edgeprog.EdgedsrVipRange) int { return int(a.Start) - int(b.Start) })
	value = edgeprog.EdgedsrVipRangeValue{Count: uint32(len(intervals)), Generation: t.clock()}
	copy(value.Ranges[:], intervals)
	return t.table.Put(raw, value)
}

func (t *RangeTable) Remove(key VIPKey) error {
	raw, err := rangeKey(key)
	if err != nil {
		return err
	}
	var value edgeprog.EdgedsrVipRangeValue
	if err = t.table.Lookup(raw, &value); errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if value.Count > MaxRangesPerVIP {
		return fmt.Errorf("invalid range count %d", value.Count)
	}
	kept := value.Ranges[:0]
	for _, r := range value.Ranges[:value.Count] {
		if r.Start != key.VPort {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		err = t.table.Delete(raw)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	next := edgeprog.EdgedsrVipRangeValue{Count: uint32(len(kept)), Generation: t.clock()}
	copy(next.Ranges[:], kept)
	return t.table.Put(raw, next)
}

func (t *RangeTable) Reconcile(live map[VIPKey]uint16, cutoff uint64) error {
	it := t.table.Iterate()
	var key edgeprog.EdgedsrVipKey
	var value edgeprog.EdgedsrVipRangeValue
	for it.Next(&key, &value) {
		if value.Generation >= cutoff {
			continue
		}
		if value.Count > MaxRangesPerVIP {
			return fmt.Errorf("invalid range count %d", value.Count)
		}
		for _, r := range value.Ranges[:value.Count] {
			k := VIPKey{Proto: key.Proto, VPort: r.Start, VIP: fromWireAddr(key.Vip)}
			if end, ok := live[k]; !ok || end != r.End {
				if err := t.Remove(k); err != nil {
					return err
				}
			}
		}
	}
	return it.Err()
}

func ReplaceOwnedVIPs(table Table, addrs []netip.Addr, generation uint64) error {
	live := map[[16]byte]bool{}
	for _, addr := range addrs {
		raw, err := toWireAddr(addr)
		if err != nil {
			return err
		}
		live[raw] = true
		key := edgeprog.EdgedsrVipAddrKey{Vip: raw}
		value := edgeprog.EdgedsrVipOwnedValue{Blocked: 1}
		if err := table.Lookup(key, &value); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		value.Generation = generation
		if err := table.Put(key, value); err != nil {
			return err
		}
	}
	it := table.Iterate()
	var key edgeprog.EdgedsrVipAddrKey
	var value edgeprog.EdgedsrVipOwnedValue
	for it.Next(&key, &value) {
		if !live[key.Vip] {
			if err := table.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
		}
	}
	return it.Err()
}

// OwnedVIPLease bounds stale forwarding when a gateway controller stops renewing.
const OwnedVIPLease = uint64(30_000_000_000)

// SetBlockedVIPs blocks the supplied owned addresses. An empty list acknowledges
// successful convergence, unblocks all owned addresses, and renews their lease.
func SetBlockedVIPs(table Table, addrs []netip.Addr) error {
	blocked := make(map[[16]byte]bool, len(addrs))
	for _, addr := range addrs {
		blocked[addr.As16()] = true
	}
	it := table.Iterate()
	var key edgeprog.EdgedsrVipAddrKey
	var value edgeprog.EdgedsrVipOwnedValue
	for it.Next(&key, &value) {
		if len(addrs) == 0 {
			value.Blocked = 0
			value.ExpiresAtNs = clockFn() + OwnedVIPLease
		} else if blocked[key.Vip] {
			value.Blocked = 1
		} else {
			continue
		}
		if err := table.Put(key, value); err != nil {
			return err
		}
	}
	return it.Err()
}

// RenewVIPs acknowledges convergence only for the supplied owned VIPs. An empty
// list is a no-op; all other addresses retain their block state and deadline.
func RenewVIPs(table Table, addrs []netip.Addr) error {
	for _, addr := range addrs {
		raw, err := toWireAddr(addr)
		if err != nil {
			return err
		}
		key := edgeprog.EdgedsrVipAddrKey{Vip: raw}
		var value edgeprog.EdgedsrVipOwnedValue
		if err := table.Lookup(key, &value); err != nil {
			return err
		}
		value.Blocked = 0
		value.ExpiresAtNs = clockFn() + OwnedVIPLease
		if err := table.Put(key, value); err != nil {
			return err
		}
	}
	return nil
}

// OwnedVIPs lists existing guards without changing their block or lease state.
func OwnedVIPs(table Table) ([]netip.Addr, error) {
	var addresses []netip.Addr
	it := table.Iterate()
	var key edgeprog.EdgedsrVipAddrKey
	var value edgeprog.EdgedsrVipOwnedValue
	for it.Next(&key, &value) {
		addresses = append(addresses, netip.AddrFrom16(key.Vip))
	}
	return addresses, it.Err()
}
