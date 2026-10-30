// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"slices"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

const MaxRangesPerKey = 16

type RangeKey struct {
	Key
	EndPort uint16
}
type RangeEntry struct {
	RangeKey
	RewriteAddr net.IP
	Generation  uint64
}

func (t *VipXlatTable) WithRangeTable(table usidmap.Table) *VipXlatTable {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.ranges = table
	return t
}

// discoverRanges runs under writeMu. A missing optional pin leaves scalar
// translations available and is retried on the next operation.
func (t *VipXlatTable) discoverRanges() error {
	if t.ranges != nil || t.openRanges == nil {
		return nil
	}
	table, err := t.openRanges()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	t.ranges = table
	return nil
}

func (t *VipXlatTable) requireRanges() error {
	if err := t.discoverRanges(); err != nil {
		return err
	}
	if t.ranges == nil {
		return errors.New("range translation is unavailable")
	}
	return nil
}

func validateRange(block uint64, argument uint16, proto uint8, start, end uint16, addr, rewrite net.IP) error {
	if err := uformat.ValidateBlock(block); err != nil {
		return err
	}
	if err := uformat.ValidateArgument(argument); err != nil {
		return err
	}
	if proto != ProtoUDP || start == 0 || end < start {
		return fmt.Errorf("invalid UDP interval %d-%d", start, end)
	}
	for _, ip := range []net.IP{addr, rewrite} {
		if ip.To16() == nil || ip.To4() != nil {
			return errors.New("range translation requires IPv6")
		}
	}
	return nil
}

func (t *VipXlatTable) registerRange(direction uint8,
	block uint64,
	argument,
	slot uint16,
	proto uint8,
	addr net.IP,
	start,
	end uint16,
	rewrite net.IP) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := t.requireRanges(); err != nil {
		return err
	}
	if err := validateRange(block, argument, proto, start, end, addr, rewrite); err != nil {
		return err
	}
	key, err := kernelKey(direction, block, argument, slot, proto, addr, 0)
	if err != nil {
		return err
	}
	// Reject stale singleton coverage rather than letting exact lookup shadow a range.
	it := t.table.Iterate()
	var exactKey prog.UsidVipXlatKey
	var exactValue prog.UsidVipXlatValue
	for it.Next(&exactKey, &exactValue) {
		port := hostToNetwork16(exactKey.Port)
		exactKey.Port = 0
		if exactKey == key && port >= start && port <= end {
			return fmt.Errorf("range overlaps singleton translation %d", port)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	raw, err := addrTo16(rewrite)
	if err != nil {
		return err
	}
	var value prog.UsidVipXlatRangeValue
	if err = t.ranges.Lookup(key, &value); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if value.Count > MaxRangesPerKey {
		return fmt.Errorf("invalid range count %d", value.Count)
	}
	entries := make([]prog.UsidVipXlatRange, 0, MaxRangesPerKey)
	for _, r := range value.Ranges[:value.Count] {
		if r.Start == start && r.Rewrite.Addr == raw {
			continue
		}
		if r.Start <= end && start <= r.End {
			return fmt.Errorf("range overlaps existing translation %d-%d", r.Start, r.End)
		}
		entries = append(entries, r)
	}
	if len(entries) >= MaxRangesPerKey {
		return errors.New("range translation capacity exceeded")
	}
	entries = append(entries, prog.UsidVipXlatRange{Start: start, End: end, Rewrite: prog.UsidVipXlatValue{Addr: raw}})
	slices.SortFunc(entries, func(a, b prog.UsidVipXlatRange) int { return int(a.Start) - int(b.Start) })
	next := prog.UsidVipXlatRangeValue{Count: uint32(len(entries)), Generation: t.clock()}
	copy(next.Ranges[:], entries)
	return t.ranges.Put(key, next)
}

func (t *VipXlatTable) RegisterIngressRange(block uint64,
	argument,
	slot uint16,
	proto uint8,
	vip net.IP,
	start,
	end uint16,
	backend net.IP) error {
	return t.registerRange(directionIngress, block, argument, slot, proto, vip, start, end, backend)
}
func (t *VipXlatTable) RegisterEgressRange(block uint64,
	argument uint16,
	proto uint8,
	backend net.IP,
	start,
	end uint16,
	vip net.IP) error {
	return t.registerRange(directionEgress, block, argument, 0, proto, backend, start, end, vip)
}

func (t *VipXlatTable) removeRange(key prog.UsidVipXlatKey, start, end uint16, rewrite [16]byte) error {
	var value prog.UsidVipXlatRangeValue
	if err := t.ranges.Lookup(key, &value); errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if value.Count > MaxRangesPerKey {
		return fmt.Errorf("invalid range count %d", value.Count)
	}
	kept := make([]prog.UsidVipXlatRange, 0, MaxRangesPerKey)
	for _, r := range value.Ranges[:value.Count] {
		if r.Start != start || r.End != end || r.Rewrite.Addr != rewrite {
			kept = append(kept, r)
		}
	}
	if len(kept) == int(value.Count) {
		return nil
	}
	if len(kept) == 0 {
		err := t.ranges.Delete(key)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	next := prog.UsidVipXlatRangeValue{Count: uint32(len(kept)), Generation: t.clock()}
	copy(next.Ranges[:], kept)
	return t.ranges.Put(key, next)
}

func (t *VipXlatTable) UnregisterRangeBindingAt(block uint64,
	argument,
	slot uint16,
	proto uint8,
	vip net.IP,
	start,
	end uint16,
	backend net.IP) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := t.requireRanges(); err != nil {
		return err
	}
	if err := validateRange(block, argument, proto, start, end, vip, backend); err != nil {
		return err
	}
	ingress, _ := kernelKey(directionIngress, block, argument, slot, proto, vip, 0)
	egress, _ := kernelKey(directionEgress, block, argument, 0, proto, backend, 0)
	rawVIP, _ := addrTo16(vip)
	rawBackend, _ := addrTo16(backend)
	return errors.Join(t.removeRange(ingress, start, end, rawBackend), t.removeRange(egress, start, end, rawVIP))
}

func (t *VipXlatTable) RangeBindingPresent(block uint64,
	argument,
	slot uint16,
	proto uint8,
	vip net.IP,
	start,
	end uint16,
	backend net.IP) (bool,
	error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := t.requireRanges(); err != nil {
		return false, err
	}
	if err := validateRange(block, argument, proto, start, end, vip, backend); err != nil {
		return false, err
	}
	keys := []struct {
		direction     uint8
		slot          uint16
		addr, rewrite net.IP
	}{{directionIngress, slot, vip, backend}, {directionEgress, 0, backend, vip}}
	for _, k := range keys {
		key, _ := kernelKey(k.direction, block, argument, k.slot, proto, k.addr, 0)
		raw, _ := addrTo16(k.rewrite)
		var value prog.UsidVipXlatRangeValue
		if err := t.ranges.Lookup(key, &value); errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		if value.Count > MaxRangesPerKey {
			return false, fmt.Errorf("invalid range count %d", value.Count)
		}
		if !slices.ContainsFunc(value.Ranges[:value.Count],
			func(r prog.UsidVipXlatRange) bool { return r.Start == start && r.End == end && r.Rewrite.Addr == raw }) {
			return false, nil
		}
	}
	return true, nil
}

func (t *VipXlatTable) ListRanges() ([]RangeEntry, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.listRanges()
}

func (t *VipXlatTable) listRanges() ([]RangeEntry, error) {
	if err := t.discoverRanges(); err != nil {
		return nil, err
	}
	if t.ranges == nil {
		return nil, nil
	}
	var entries []RangeEntry
	it := t.ranges.Iterate()
	var key prog.UsidVipXlatKey
	var value prog.UsidVipXlatRangeValue
	for it.Next(&key, &value) {
		if value.Count > MaxRangesPerKey {
			return nil, fmt.Errorf("invalid range count %d", value.Count)
		}
		for _, r := range value.Ranges[:value.Count] {
			entries = append(entries,
				RangeEntry{RangeKey: RangeKey{Key: Key{Block: key.Block,
					Argument:  key.Argument,
					Slot:      key.Slot,
					Proto:     key.Proto,
					Direction: Direction(key.Direction),
					Addr:      fromWire(key.Addr),
					Port:      r.Start},
					EndPort: r.End},
					RewriteAddr: net.IP(fromWire(r.Rewrite.Addr).AsSlice()),
					Generation:  value.Generation})
		}
	}
	return entries, it.Err()
}

func (t *VipXlatTable) ReconcileRanges(live map[RangeKey]struct{}, cutoff uint64) ([]RangeEntry, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	entries, err := t.listRanges()
	if err != nil {
		return nil, err
	}
	var removed []RangeEntry
	for _, entry := range entries {
		if _, ok := live[entry.RangeKey]; ok || entry.Generation >= cutoff {
			continue
		}
		key,
			err := kernelKey(uint8(entry.Direction),
			entry.Block,
			entry.Argument,
			entry.Slot,
			entry.Proto,
			net.IP(entry.Addr.AsSlice()),
			0)
		if err != nil {
			return removed, err
		}
		raw, err := addrTo16(entry.RewriteAddr)
		if err != nil {
			return removed, err
		}
		if err = t.removeRange(key, entry.Port, entry.EndPort, raw); err != nil {
			return removed, err
		}
		removed = append(removed, entry)
	}
	return removed, nil
}

// SupportsPortRanges reports whether the compact range map is available.
func (t *VipXlatTable) SupportsPortRanges() bool {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.discoverRanges() == nil && t.ranges != nil
}

// rejectRangeOverlap is called under writeMu before publishing a singleton.
func (t *VipXlatTable) rejectRangeOverlap(key prog.UsidVipXlatKey, port uint16) error {
	if err := t.discoverRanges(); err != nil {
		return err
	}
	if t.ranges == nil {
		return nil
	}
	key.Port = 0
	var value prog.UsidVipXlatRangeValue
	if err := t.ranges.Lookup(key, &value); errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if value.Count > MaxRangesPerKey {
		return errors.New("invalid range count")
	}
	for _, r := range value.Ranges[:value.Count] {
		if port >= r.Start && port <= r.End {
			return fmt.Errorf("singleton overlaps interval %d-%d", r.Start, r.End)
		}
	}
	return nil
}
