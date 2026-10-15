// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tpmap writes the uSID datapath's interface traffic policy maps:
// the enforcement mode, the managed-interface table, the NAT locators that
// classify a route or an outer source as a NAT shard's, and the per-interface,
// per-direction snapshots tp_decide evaluates.
//
// A snapshot is published by creating a new inner map, filling it, and
// inserting it with one update of tp_binding_table. The kernel waits for
// every program that could hold the replaced snapshot to finish before that
// update returns (maybe_wait_bpf_programs in kernel/bpf/syscall.c), so once
// Publish returns, counter rows only the old snapshot referenced can be
// reused. See docs/enhancements/networking/interface-traffic-policy.
package tpmap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/trafficpolicy"
)

// Enforcement modes, tp_state.mode.
const (
	ModeOff     uint32 = 0
	ModeAudit   uint32 = 1
	ModeEnforce uint32 = 2
)

// Directions, the workload's.
const (
	DirIngress uint32 = 0
	DirEgress  uint32 = 1
)

// Interface kinds, tp_iface_table.kind.
const (
	KindTenant uint32 = 1
	KindInfra  uint32 = 2
)

// Fallback reasons, the fixed metric enum, in the datapath's order.
const (
	ReasonNoMatch             uint8 = 0
	ReasonPolicyUnavailable   uint8 = 1
	ReasonParseError          uint8 = 2
	ReasonClassificationError uint8 = 3
	reasonCount                     = 4
)

// ReasonNames are the metric label values of the fallback reasons.
var ReasonNames = [reasonCount]string{"no_match", "policy_unavailable", "parse_error", "classification_error"}

// RuleCounterRows is tp_rule_counters' size.
const RuleCounterRows = 16384

// slotSize is the size of one snapshot slot, an entry or the header.
var slotSize = uint32(binary.Size(prog.UsidTpEntry{})) //nolint:gosec // a fixed struct size

// SnapshotSpec is the spec of one tp_binding_table inner map, which must match
// the compiled template exactly: the kernel refuses an inner map of any other
// shape.
var SnapshotSpec = ebpf.MapSpec{
	Name:       "tp_snapshot",
	Type:       ebpf.Array,
	KeySize:    4,
	ValueSize:  slotSize,
	MaxEntries: galacticv1alpha1.MaxCompiledEntries + 1,
}

// Maps are the traffic policy maps of a loaded or pinned uSID datapath.
type Maps struct {
	State            *ebpf.Map
	Interfaces       *ebpf.Map
	InterfaceAddrs   *ebpf.Map
	Bindings         *ebpf.Map
	NATLocators      *ebpf.Map
	RuleCounters     *ebpf.Map
	FallbackCounters *ebpf.Map
}

// FromObjects returns the traffic policy maps of objs.
func FromObjects(objs *prog.UsidObjects) *Maps {
	return &Maps{
		State:            objs.TpState,
		Interfaces:       objs.TpIfaceTable,
		InterfaceAddrs:   objs.TpIfaceAddrTable,
		Bindings:         objs.TpBindingTable,
		NATLocators:      objs.TpNatLocatorTable,
		RuleCounters:     objs.TpRuleCounters,
		FallbackCounters: objs.TpFallbackCounters,
	}
}

// SetState sets the enforcement mode and whether the NAT locators are
// complete.
func (m *Maps) SetState(mode uint32, natLocatorsSynced bool) error {
	v := prog.UsidTpStateValue{Mode: mode}
	if natLocatorsSynced {
		v.NatLocatorsSynced = 1
	}
	if err := m.State.Put(uint32(0), v); err != nil {
		return fmt.Errorf("write tp_state: %w", err)
	}
	return nil
}

// PutInterface marks ifindex as an interface Galactic manages, with its
// lifetime's policy token. Its zeroed fallback counter rows are created
// first, so its first packet is attributed. A row that already exists for
// this lifetime keeps its counts.
func (m *Maps) PutInterface(ifindex uint32, token uint64, kind uint32) error {
	zero := make([]prog.UsidTpCounter, ebpf.MustPossibleCPU())
	for _, dir := range []uint32{DirIngress, DirEgress} {
		for reason := range uint8(reasonCount) {
			err := m.FallbackCounters.Update(FallbackKey(ifindex, token, dir, reason), zero, ebpf.UpdateNoExist)
			if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
				return fmt.Errorf("create fallback counters for ifindex %d: %w", ifindex, err)
			}
		}
	}
	if err := m.Interfaces.Put(ifindex, prog.UsidTpIfaceValue{PolicyToken: token, Kind: kind}); err != nil {
		return fmt.Errorf("write tp_iface_table[%d]: %w", ifindex, err)
	}
	return nil
}

// PutInterfaceAddr records one of ifindex's assigned addresses, which the
// link-operation checks accept as an ARP or neighbor discovery source.
func (m *Maps) PutInterfaceAddr(ifindex uint32, addr netip.Addr) error {
	k := prog.UsidTpIfaceAddrKey{Ifindex: ifindex, Family: 6}
	if addr.Is4() {
		k.Family = 4
		a4 := addr.As4()
		copy(k.Addr[:], a4[:])
	} else {
		k.Addr = addr.As16()
	}
	if err := m.InterfaceAddrs.Put(k, uint8(1)); err != nil {
		return fmt.Errorf("write tp_iface_addr_table: %w", err)
	}
	return nil
}

// FallbackKey is the tp_fallback_counters key of one interface lifetime,
// direction and reason.
func FallbackKey(ifindex uint32, token uint64, dir uint32, reason uint8) prog.UsidTpFallbackKey {
	return prog.UsidTpFallbackKey{Ifindex: ifindex, Direction: uint8(dir), Reason: reason, PolicyToken: token}
}

// AddNATLocator records sid's locator, its top 64 bits, as a NAT shard's.
// Shard locators are disjoint from every router locator, so an entry is never
// removed while the agent runs: a stale one can classify nothing wrongly.
func (m *Maps) AddNATLocator(sid netip.Addr) error {
	b := sid.As16()
	if err := m.NATLocators.Put(binary.NativeEndian.Uint64(b[:8]), uint8(1)); err != nil {
		return fmt.Errorf("write tp_nat_locator_table: %w", err)
	}
	return nil
}

// Publish installs entries as ifindex's snapshot in dir, its rules counting
// into rows counterBase onward. The rows must already be zeroed (see
// ZeroCounters). When Publish returns, no packet can still be evaluating the
// snapshot it replaced.
func (m *Maps) Publish(ifindex, dir uint32, token uint64, counterBase uint32, entries []trafficpolicy.Entry) error {
	if len(entries) > galacticv1alpha1.MaxCompiledEntries {
		return fmt.Errorf("%d entries, more than the limit of %d", len(entries), galacticv1alpha1.MaxCompiledEntries)
	}
	for _, e := range entries {
		if uint64(counterBase)+uint64(e.Rule) >= RuleCounterRows {
			return fmt.Errorf("rule %d's counter row %d is outside tp_rule_counters", e.Rule, uint64(counterBase)+uint64(e.Rule))
		}
	}
	inner, err := ebpf.NewMap(&SnapshotSpec)
	if err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}
	defer inner.Close() //nolint:errcheck // the outer map holds its own reference once inserted

	count := uint32(len(entries)) //nolint:gosec // bounded above
	header := prog.UsidTpHeader{PolicyToken: token, CounterBase: counterBase, Count: count}
	if err := inner.Put(uint32(0), header); err != nil {
		return fmt.Errorf("write snapshot header: %w", err)
	}
	for i, e := range entries {
		if err := inner.Put(uint32(i+1), EncodeEntry(e)); err != nil { //nolint:gosec // bounded above
			return fmt.Errorf("write snapshot entry %d: %w", i, err)
		}
	}
	if err := m.Bindings.Put(prog.UsidTpBindingKey{Ifindex: ifindex, Direction: dir}, inner); err != nil {
		return fmt.Errorf("bind snapshot to ifindex %d direction %d: %w", ifindex, dir, err)
	}
	return nil
}

// Invalidate removes ifindex's snapshot in dir, so it denies as
// policy_unavailable. It needs no allocation, so it works when publishing a
// replacement cannot.
func (m *Maps) Invalidate(ifindex, dir uint32) error {
	err := m.Bindings.Delete(prog.UsidTpBindingKey{Ifindex: ifindex, Direction: dir})
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("unbind ifindex %d direction %d: %w", ifindex, dir, err)
	}
	return nil
}

// ZeroCounters resets rule counter rows [base, base+n), so a new counter
// interval starts at zero.
func (m *Maps) ZeroCounters(base, n uint32) error {
	zero := make([]prog.UsidTpCounter, ebpf.MustPossibleCPU())
	for i := base; i < base+n; i++ {
		if err := m.RuleCounters.Put(i, zero); err != nil {
			return fmt.Errorf("zero rule counter %d: %w", i, err)
		}
	}
	return nil
}

// EncodeEntry is e in the datapath's layout.
func EncodeEntry(e trafficpolicy.Entry) prog.UsidTpEntry {
	out := prog.UsidTpEntry{
		Flags:    uint16(e.Flags),
		Rule:     e.Rule,
		Path:     uint8(e.Path),
		Family:   uint8(e.Family),
		Proto:    e.Proto,
		IcmpType: e.ICMPType,
		IcmpCode: e.ICMPCode,
		SportLo:  e.SourcePorts.Start,
		SportHi:  e.SourcePorts.End,
		DportLo:  e.DestPorts.Start,
		DportHi:  e.DestPorts.End,
	}
	if e.Source.IsValid() {
		out.Src, out.SrcMask = prefixWords(e.Source)
	}
	if e.Destination.IsValid() {
		out.Dst, out.DstMask = prefixWords(e.Destination)
	}
	return out
}

// prefixWords is p's address and mask as the two native-endian words the
// datapath loads them as, an IPv4 address in the first 4 bytes.
func prefixWords(p netip.Prefix) (addr, mask [2]uint64) {
	var a, m [16]byte
	if p.Addr().Is4() {
		a4 := p.Addr().As4()
		copy(a[:], a4[:])
	} else {
		a = p.Addr().As16()
	}
	for i := range p.Bits() {
		m[i/8] |= 0x80 >> (i % 8)
	}
	for i := range a {
		a[i] &= m[i]
	}
	return [2]uint64{binary.NativeEndian.Uint64(a[:8]), binary.NativeEndian.Uint64(a[8:])},
		[2]uint64{binary.NativeEndian.Uint64(m[:8]), binary.NativeEndian.Uint64(m[8:])}
}
