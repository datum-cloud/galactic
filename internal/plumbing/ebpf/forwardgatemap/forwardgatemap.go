// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package forwardgatemap reads and writes the uSID datapath's Galactic Edge
// forwarding gate: edge_link_table, which marks a host link as an edge
// attachment's and holds its own address, and edge_gate_table, which holds
// one CLOCK_BOOTTIME deadline per prefix the link may carry. The datapath
// drops every packet on an edge link whose address is neither the link's
// own nor under an unexpired gate (internal/plumbing/ebpf/prog/usid.c).
//
// galactic-edge is the only writer.
package forwardgatemap

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// Gate is one prefix's gate on a link.
type Gate struct {
	// Deadline is when forwarding stops, on CLOCK_BOOTTIME.
	Deadline time.Duration
	// RenewStart is the lease renewal Deadline was computed from, on the
	// same clock.
	RenewStart time.Duration
	// Epoch is the accepted claim epoch the gate is for.
	Epoch uint64
}

// Stats are the packets each check dropped for want of an open gate.
type Stats struct {
	Ingress, Egress, Deliver uint64
}

type linkValue struct {
	Addr [16]byte
}

// gateKey is struct edge_gate_key: the prefix length in host order, then the
// ifindex and address bytes the trie matches.
type gateKey struct {
	PrefixLen uint32
	Ifindex   uint32
	Addr      [16]byte
}

type gateValue struct {
	DeadlineNS   uint64
	RenewStartNS uint64
	Epoch        uint64
}

// ifindexBits is the part of a gate key's prefix length the ifindex takes.
const ifindexBits = 32

// Table is the pinned gate maps.
type Table struct {
	links *ebpf.Map
	gates *ebpf.Map
	stats *ebpf.Map
}

// OpenPinned opens the gate maps pinned under pinDir.
func OpenPinned(pinDir string) (*Table, error) {
	t := &Table{}
	for _, m := range []struct {
		name string
		dst  **ebpf.Map
	}{
		{prog.UsidMapEdgeLinkTable, &t.links},
		{prog.UsidMapEdgeGateTable, &t.gates},
		{prog.UsidMapEdgeGateStats, &t.stats},
	} {
		opened, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, m.name), nil)
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("forwardgatemap: open pinned map %q: %w", m.name, err)
		}
		*m.dst = opened
	}
	return t, nil
}

// Close releases the maps; the pins and their contents remain.
func (t *Table) Close() error {
	var errs []error
	for _, m := range []*ebpf.Map{t.links, t.gates, t.stats} {
		if m != nil {
			errs = append(errs, m.Close())
		}
	}
	return errors.Join(errs...)
}

// SetLink marks ifindex as an edge host link whose own address is addr. From
// then on the link carries nothing else without an open gate.
func (t *Table) SetLink(ifindex uint32, addr netip.Addr) error {
	if !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("forwardgatemap: link address %s is not IPv6", addr)
	}
	if err := t.links.Put(ifindex, linkValue{Addr: addr.As16()}); err != nil {
		return fmt.Errorf("forwardgatemap: set link %d: %w", ifindex, err)
	}
	return nil
}

// Link returns ifindex's own address, if it is an edge link.
func (t *Table) Link(ifindex uint32) (netip.Addr, bool, error) {
	var v linkValue
	if err := t.links.Lookup(ifindex, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return netip.Addr{}, false, nil
		}
		return netip.Addr{}, false, fmt.Errorf("forwardgatemap: read link %d: %w", ifindex, err)
	}
	return netip.AddrFrom16(v.Addr), true, nil
}

// DeleteGates closes every gate on ifindex: the link then carries only its
// own address. Absent rows are not errors.
func (t *Table) DeleteGates(ifindex uint32) error {
	gates, err := t.Gates(ifindex)
	if err != nil {
		return err
	}
	var errs []error
	for p := range gates {
		errs = append(errs, t.Delete(ifindex, p))
	}
	return errors.Join(errs...)
}

// DeleteLink removes ifindex's gates, then its link row. Call it once the
// link is deleted and before its ifindex can be reused, so no later
// interface inherits the row. Absent rows are not errors.
func (t *Table) DeleteLink(ifindex uint32) error {
	if err := t.DeleteGates(ifindex); err != nil {
		return err
	}
	if err := t.links.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("forwardgatemap: delete link %d: %w", ifindex, err)
	}
	return nil
}

func key(ifindex uint32, p netip.Prefix) (gateKey, error) {
	if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p != p.Masked() {
		return gateKey{}, fmt.Errorf("forwardgatemap: prefix %s is not a masked IPv6 prefix", p)
	}
	return gateKey{PrefixLen: ifindexBits + uint32(p.Bits()), Ifindex: ifindex, Addr: p.Addr().As16()}, nil
}

// Set writes prefix's gate on ifindex.
func (t *Table) Set(ifindex uint32, prefix netip.Prefix, g Gate) error {
	k, err := key(ifindex, prefix)
	if err != nil {
		return err
	}
	v := gateValue{DeadlineNS: uint64(g.Deadline), RenewStartNS: uint64(g.RenewStart), Epoch: g.Epoch}
	if err := t.gates.Put(k, v); err != nil {
		return fmt.Errorf("forwardgatemap: set gate %s on %d: %w", prefix, ifindex, err)
	}
	return nil
}

// Delete closes prefix's gate on ifindex. An absent gate is not an error.
func (t *Table) Delete(ifindex uint32, prefix netip.Prefix) error {
	k, err := key(ifindex, prefix)
	if err != nil {
		return err
	}
	if err := t.gates.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("forwardgatemap: delete gate %s on %d: %w", prefix, ifindex, err)
	}
	return nil
}

// Gates returns every gate on ifindex, expired or not.
func (t *Table) Gates(ifindex uint32) (map[netip.Prefix]Gate, error) {
	out := map[netip.Prefix]Gate{}
	var k gateKey
	var v gateValue
	it := t.gates.Iterate()
	for it.Next(&k, &v) {
		if k.Ifindex != ifindex || k.PrefixLen < ifindexBits {
			continue
		}
		p := netip.PrefixFrom(netip.AddrFrom16(k.Addr), int(k.PrefixLen-ifindexBits))
		out[p] = Gate{Deadline: time.Duration(v.DeadlineNS), RenewStart: time.Duration(v.RenewStartNS), Epoch: v.Epoch}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("forwardgatemap: list gates of %d: %w", ifindex, err)
	}
	return out, nil
}

// Links returns every edge link's ifindex and own address.
func (t *Table) Links() (map[uint32]netip.Addr, error) {
	out := map[uint32]netip.Addr{}
	var k uint32
	var v linkValue
	it := t.links.Iterate()
	for it.Next(&k, &v) {
		out[k] = netip.AddrFrom16(v.Addr)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("forwardgatemap: list links: %w", err)
	}
	return out, nil
}

// Stats sums the drop counters over every CPU.
func (t *Table) Stats() (Stats, error) {
	var s Stats
	for i, dst := range []*uint64{&s.Ingress, &s.Egress, &s.Deliver} {
		var per []uint64
		if err := t.stats.Lookup(uint32(i), &per); err != nil {
			return Stats{}, fmt.Errorf("forwardgatemap: read stats: %w", err)
		}
		for _, n := range per {
			*dst += n
		}
	}
	return s, nil
}
