// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66map

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
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

// ConnKey identifies one nat66_conn_table row, mirroring the datapath's forward
// and reverse row layout. TenantArg is in host order, the datapath already
// returning it that way; the ports are the packet's own wire-order values.
type ConnKey struct {
	Proto     uint8
	TenantArg uint16
	Sport     uint16
	Dport     uint16
	Saddr     netip.Addr
	Daddr     netip.Addr
}

// ConnEntry is one fully decoded nat66_conn_table row, decoupled from
// nat66prog.Nat66ConnValue's cilium/ebpf/BTF-generated field layout.
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

// ConnTable is the read-only accessor for nat66_conn_table; see the package doc
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

func toWireConnKey(key ConnKey) (nat66prog.Nat66ConnKey, error) {
	if err := validateAddr("conn key source address", key.Saddr); err != nil {
		return nat66prog.Nat66ConnKey{}, err
	}
	if err := validateAddr("conn key destination address", key.Daddr); err != nil {
		return nat66prog.Nat66ConnKey{}, err
	}
	return nat66prog.Nat66ConnKey{
		Proto:     key.Proto,
		TenantArg: key.TenantArg,
		Sport:     beU16(key.Sport),
		Dport:     beU16(key.Dport),
		Saddr:     key.Saddr.As16(),
		Daddr:     key.Daddr.As16(),
	}, nil
}

func fromWireConnKey(wireKey nat66prog.Nat66ConnKey) ConnKey {
	return ConnKey{
		Proto:     wireKey.Proto,
		TenantArg: wireKey.TenantArg,
		Sport:     beU16(wireKey.Sport),
		Dport:     beU16(wireKey.Dport),
		Saddr:     netip.AddrFrom16(wireKey.Saddr),
		Daddr:     netip.AddrFrom16(wireKey.Daddr),
	}
}

func fromWireConnValue(key ConnKey, value nat66prog.Nat66ConnValue) ConnEntry {
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

// Get reads the nat66_conn_table entry for key, reporting whether it
// exists.
func (t *ConnTable) Get(key ConnKey) (ConnEntry, bool, error) {
	wireKey, err := toWireConnKey(key)
	if err != nil {
		return ConnEntry{}, false, fmt.Errorf("nat66map: nat66_conn_table: get %+v: %w", key, err)
	}

	var value nat66prog.Nat66ConnValue
	if err := t.table.Lookup(wireKey, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ConnEntry{}, false, nil
		}
		return ConnEntry{}, false, fmt.Errorf("nat66map: nat66_conn_table: get %+v: %w", key, err)
	}
	return fromWireConnValue(key, value), true, nil
}

// List returns every entry currently in nat66_conn_table, in unspecified order.
// The map evicts under live traffic, so the result is a point-in-time snapshot:
// a row present in one call may be gone by the next.
func (t *ConnTable) List() ([]ConnEntry, error) {
	var (
		entries []ConnEntry
		rawKey  nat66prog.Nat66ConnKey
		value   nat66prog.Nat66ConnValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		key := fromWireConnKey(rawKey)
		entries = append(entries, fromWireConnValue(key, value))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("nat66map: nat66_conn_table: list: %w", err)
	}
	return entries, nil
}
