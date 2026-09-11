// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natmap

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// beU16 swaps a uint16 between host and network byte order. A full 2-byte swap
// is its own inverse, so one function serves both directions. Needed because the
// generated Go structs store a big-endian C field as a plain uint16, which the
// marshalling writes in host order with no swap. Duplicated rather than imported
// from a sibling map package; see the package doc comment for why this package
// depends on none of them.
func beU16(v uint16) uint16 {
	return v<<8 | v>>8
}

// ConnKey identifies one nat_conn_table row, mirroring the datapath's forward
// and reverse row layout. TenantArg is in host order, the datapath already
// returning it that way; the ports are the packet's own wire-order values.
type ConnKey struct {
	// Family is natprog.FamilyIPv6 for a NAT66 flow or natprog.FamilyIPv4 for a
	// NAT64 one. It is part of the key, not a description of it: a NAT64 row
	// stores its IPv4 addresses IPv4-mapped, which without this byte could
	// alias a genuine IPv6 flow inside ::ffff:0:0/96.
	Family uint8

	Proto     uint8
	TenantArg uint16
	Sport     uint16
	Dport     uint16
	Saddr     netip.Addr
	Daddr     netip.Addr
}

// ConnEntry is one fully decoded nat_conn_table row, decoupled from
// natprog.NatConnValue's cilium/ebpf/BTF-generated field layout.
type ConnEntry struct {
	ConnKey

	// BackendAddr and BackendPort are the tenant backend's facing address and
	// port, present in both the forward and reverse row's value.
	BackendAddr netip.Addr
	BackendPort uint16

	// DestAddr/DestPort are the internet destination's own address/port.
	DestAddr netip.Addr
	DestPort uint16

	// ShardPort is this shard's own allocated masquerade port for this
	// flow.
	ShardPort uint16

	// BackendUSID is the tenant backend's own worker-node SRv6 uSID, used
	// to re-encapsulate a reply back toward it (handle_return).
	BackendUSID netip.Addr

	// Proto is the value's own copy of the protocol, always equal to the key's
	// by construction and exposed separately only because the kernel value
	// carries its own field.
	Proto uint8
}

// ConnTable is the read-only accessor for nat_conn_table; see the package doc
// comment for why this package never writes it. Get and List exist for
// observability, and nothing in the control plane depends on reading them.
type ConnTable struct {
	table Table
}

// NewConnTable wraps table as a ConnTable. Production callers pass a kernel
// table over the loaded map; tests pass a fake.
func NewConnTable(table Table) *ConnTable {
	return &ConnTable{table: table}
}

func toWireConnKey(key ConnKey) (natprog.NatConnKey, error) {
	if err := validateConnAddr("conn key source address", key.Saddr); err != nil {
		return natprog.NatConnKey{}, err
	}
	if err := validateConnAddr("conn key destination address", key.Daddr); err != nil {
		return natprog.NatConnKey{}, err
	}
	return natprog.NatConnKey{
		Family:    key.Family,
		Proto:     key.Proto,
		TenantArg: key.TenantArg,
		Sport:     beU16(key.Sport),
		Dport:     beU16(key.Dport),
		Saddr:     key.Saddr.As16(),
		Daddr:     key.Daddr.As16(),
	}, nil
}

func fromWireConnKey(wireKey natprog.NatConnKey) ConnKey {
	return ConnKey{
		Family:    wireKey.Family,
		Proto:     wireKey.Proto,
		TenantArg: wireKey.TenantArg,
		Sport:     beU16(wireKey.Sport),
		Dport:     beU16(wireKey.Dport),
		Saddr:     netip.AddrFrom16(wireKey.Saddr),
		Daddr:     netip.AddrFrom16(wireKey.Daddr),
	}
}

// validateConnAddr accepts any address the session table legitimately holds.
// Unlike the shard-identity addresses, a connection row's addresses may be
// IPv4-mapped: that is how a NAT64 flow's IPv4 peer and masquerade address are
// stored in the 16-byte key fields.
func validateConnAddr(field string, addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%s is not a valid address", field)
	}
	if !addr.Is6() {
		return fmt.Errorf("%s %s must be stored in 16-byte form (IPv4 addresses IPv4-mapped)", field, addr)
	}
	return nil
}

func fromWireConnValue(key ConnKey, value natprog.NatConnValue) ConnEntry {
	return ConnEntry{
		ConnKey:     key,
		BackendAddr: netip.AddrFrom16(value.BackendAddr),
		BackendPort: beU16(value.BackendPort),
		DestAddr:    netip.AddrFrom16(value.DestAddr),
		DestPort:    beU16(value.DestPort),
		ShardPort:   beU16(value.ShardPort),
		BackendUSID: netip.AddrFrom16(value.BackendUsid),
		Proto:       value.Proto,
	}
}

// Get reads the nat_conn_table entry for key, reporting whether it
// exists.
func (t *ConnTable) Get(key ConnKey) (ConnEntry, bool, error) {
	wireKey, err := toWireConnKey(key)
	if err != nil {
		return ConnEntry{}, false, fmt.Errorf("natmap: nat_conn_table: get %+v: %w", key, err)
	}

	var value natprog.NatConnValue
	if err := t.table.Lookup(wireKey, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ConnEntry{}, false, nil
		}
		return ConnEntry{}, false, fmt.Errorf("natmap: nat_conn_table: get %+v: %w", key, err)
	}
	return fromWireConnValue(key, value), true, nil
}

// List returns every entry currently in nat_conn_table, in unspecified order.
// The map evicts under live traffic, so the result is a point-in-time snapshot:
// a row present in one call may be gone by the next.
func (t *ConnTable) List() ([]ConnEntry, error) {
	var (
		entries []ConnEntry
		rawKey  natprog.NatConnKey
		value   natprog.NatConnValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		key := fromWireConnKey(rawKey)
		entries = append(entries, fromWireConnValue(key, value))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("natmap: nat_conn_table: list: %w", err)
	}
	return entries, nil
}
