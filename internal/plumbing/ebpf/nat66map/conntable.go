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

// beU16 converts v between host and big-endian ("network") representation
// by a full 2-byte swap -- its own inverse, so this same function is used
// for both directions. Required because nat66prog's generated Go structs
// store a C __be16 field as a plain uint16, and cilium/ebpf's BTF-based
// marshalling writes it using the host's native (little-endian, on every
// architecture this repo targets) byte order with no swap of its own. This
// duplicates edgemap's identically-named helper rather than importing it --
// see doc.go for why this package does not depend on edgemap.
func beU16(v uint16) uint16 {
	return v<<8 | v>>8
}

// ConnKey identifies one nat66_conn_table row -- see nat66.c's struct
// conn_key doc comment for the forward/reverse row layout this mirrors.
// TenantArg is host-order (nat66.c's read_argument already returns it in
// host order, not wire order, so unlike Sport/Dport it needs no beU16
// swap); Sport/Dport are the packet's own wire-order (__be16) ports.
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

	// BackendAddr/BackendPort are the tenant backend's own facing
	// address/port -- present in both the forward and reverse row's value
	// (nat66.c's struct conn_value comment).
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

	// Proto is the value's own copy of the protocol, read back
	// independently of ConnKey.Proto (both are always equal by
	// construction -- nat66.c never writes them differently -- exposed
	// separately only because Nat66ConnValue carries its own field).
	Proto uint8
}

// ConnTable is the read-only accessor for nat66_conn_table -- see doc.go
// for why this package never writes to it. Get/List exist purely for
// observability/metrics (e.g. a future admin CLI or diagnostics endpoint);
// nothing in this codebase's control plane depends on reading it today.
type ConnTable struct {
	table Table
}

// NewConnTable wraps table as a ConnTable. Production callers pass a
// KernelTable wrapping a loaded *nat66prog.Nat66Objects's Nat66ConnTable
// map; tests pass a fake Table.
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

// List returns every entry currently in nat66_conn_table, in unspecified
// order. Since this is an LRU-evicting map under live traffic, the result
// is only ever a point-in-time snapshot -- a row present in one List call
// may be gone (evicted, or aged out) by the next.
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
