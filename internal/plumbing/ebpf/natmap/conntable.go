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

	// EncapSrc is the source of the SRv6 outer header a forward row's packet
	// arrived in -- the address of the worker node it was encapsulated from.
	// Zero on a reverse row, whose reply arrives from the internet rather than
	// across the fabric and whose uniqueness comes from the shard's own
	// (address, masquerade port) pair instead.
	//
	// It is part of the key because TenantArg alone does not identify a tenant
	// fabric-wide: Arguments are allocated per BGPRouter, so two tenants on
	// different nodes routinely hold the same one. See the datapath's own
	// conn_key comment.
	EncapSrc netip.Addr
}

// ConnEntry is one fully decoded nat_conn_table row, decoupled from
// natprog.NatConnValue's cilium/ebpf/BTF-generated field layout.
//
// A row whose Proto is ICMPv6 (58) is an Echo session, and its port fields hold
// Echo Identifiers instead: BackendPort is the tenant's own Identifier,
// ShardPort the masquerade Identifier the shard replaced it with, and DestPort
// is zero. The key follows the same convention -- a forward row's Sport is the
// tenant's Identifier and its Dport zero, a reverse row's Sport zero and its
// Dport the masquerade Identifier. Echo sessions share the table, and its LRU
// capacity, with TCP and UDP; see the datapath's nat_conn_table comment, which
// also covers idle expiry.
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

	// BackendTenantArg is the forward key's TenantArg, carried in both rows so
	// a reverse row, whose key holds zero there, names its forward row.
	BackendTenantArg uint16

	// State holds natprog.SessionTCP* bits, and LastSeen the second of the
	// monotonic clock the session last translated a packet. Both are kept
	// current on the reverse row only; a forward row's are from when it was
	// written.
	State    uint8
	LastSeen uint32
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
	wire := natprog.NatConnKey{
		Family:    key.Family,
		Proto:     key.Proto,
		TenantArg: key.TenantArg,
		Sport:     beU16(key.Sport),
		Dport:     beU16(key.Dport),
		Saddr:     key.Saddr.As16(),
		Daddr:     key.Daddr.As16(),
	}
	// Left zero when unset, which is what a reverse row carries.
	if key.EncapSrc.IsValid() {
		if err := validateConnAddr("conn key encapsulation source", key.EncapSrc); err != nil {
			return natprog.NatConnKey{}, err
		}
		wire.EncapSrc = key.EncapSrc.As16()
	}
	return wire, nil
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
		EncapSrc:  encapSrcFromWire(wireKey.EncapSrc),
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

// encapSrcFromWire decodes a forward row's encapsulation source, returning the
// zero Addr for the all-zero field a reverse row carries.
//
// Decoding that as "::" instead would be a round-trip asymmetry: toWireConnKey
// writes zeros for an unset source, so "::" would come back out where nothing
// went in, and a caller could not tell a reverse row from a forward row
// encapsulated from the unspecified address.
func encapSrcFromWire(raw [16]byte) netip.Addr {
	if raw == ([16]byte{}) {
		return netip.Addr{}
	}
	return netip.AddrFrom16(raw)
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

		BackendTenantArg: value.TenantArg,
		State:            value.State,
		LastSeen:         value.LastSeen,
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

// Session protocols as CountSessions reports them. A row of any protocol other
// than TCP or UDP is an ICMP Echo session, matching the datapath's
// session_timeout, which gives every such row the ICMP timeout.
const (
	SessionProtoTCP  = "tcp"
	SessionProtoUDP  = "udp"
	SessionProtoICMP = "icmp"
)

const (
	ipprotoTCP = 6
	ipprotoUDP = 17
	dnsPort    = 53
)

// SessionKey groups live sessions by their key's family and their protocol.
type SessionKey struct {
	Family uint8
	Proto  string
}

// SessionCounts is one walk of nat_conn_table.
type SessionCounts struct {
	// Rows counts every row by its key's family, expired sessions included.
	// A whole session holds two rows.
	Rows map[uint8]int

	// Live counts reverse rows whose session has not expired, one per live
	// session.
	Live map[SessionKey]int

	// OldestAge is the largest age in seconds, now minus last_seen, of any
	// reverse row, expired ones included. Expired rows stay until the LRU
	// evicts them or a claim reuses their port, so on a full table this is
	// roughly how long an idle row survives before eviction. HasReverse is
	// false, and OldestAge zero, when the walk found no reverse row.
	OldestAge  uint32
	HasReverse bool
}

// sessionProto names a row's protocol as SessionKey reports it.
func sessionProto(proto uint8) string {
	switch proto {
	case ipprotoTCP:
		return SessionProtoTCP
	case ipprotoUDP:
		return SessionProtoUDP
	default:
		return SessionProtoICMP
	}
}

// sessionTimeout mirrors the datapath's session_timeout, in seconds.
func sessionTimeout(value *natprog.NatConnValue) uint32 {
	switch value.Proto {
	case ipprotoTCP:
		if value.State&(natprog.SessionTCPEstablished|natprog.SessionTCPClosing) == natprog.SessionTCPEstablished {
			return natprog.TimeoutTCPEstablished
		}
		return natprog.TimeoutTCPTransitory
	case ipprotoUDP:
		if beU16(value.DestPort) == dnsPort {
			return natprog.TimeoutUDPDNS
		}
		return natprog.TimeoutUDP
	default:
		return natprog.TimeoutICMP
	}
}

// rowAge is how many seconds before now a row was last seen. now is the
// datapath's clock: CLOCK_MONOTONIC in whole seconds, truncated to 32 bits. The
// subtraction wraps as the datapath's does, so a stamp from before the last
// wrap still reads as its true age.
//
// Unlike the datapath, a stamp after now reads as age zero. The walk reads now
// once and then takes a while, and the datapath keeps refreshing rows on other
// CPUs meanwhile; without the clamp, a session refreshed mid-walk would wrap to
// an age of about 2^32 seconds and read as long expired.
func rowAge(lastSeen, now uint32) uint32 {
	age := now - lastSeen
	if int32(age) < 0 { //nolint:gosec // reinterpreting the wrapped difference is the point
		return 0
	}
	return age
}

// sessionExpired mirrors the datapath's session_expired, with rowAge's clamp.
func sessionExpired(value *natprog.NatConnValue, now uint32) bool {
	return rowAge(value.LastSeen, now) > sessionTimeout(value)
}

// CountSessions counts rows by family, and live sessions by family and
// protocol, as of now (see rowAge for its clock). Only a reverse row, whose key
// carries no encapsulation source, is checked for liveness: a forward row's
// last_seen records when it was written and is never refreshed. The datapath
// copies a forward row's encapsulation source from the packet's outer header,
// so a packet sent from "::" would leave a forward row that is counted here as a
// session; no legitimate fabric node sends from that address.
//
// The datapath inserts and evicts rows during the walk, which can restart it
// or cut it short. The counts gathered so far are returned alongside any error,
// and are approximate either way.
func (t *ConnTable) CountSessions(now uint32) (SessionCounts, error) {
	var (
		counts = SessionCounts{Rows: map[uint8]int{}, Live: map[SessionKey]int{}}
		rawKey natprog.NatConnKey
		value  natprog.NatConnValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		counts.Rows[rawKey.Family]++
		if rawKey.EncapSrc != ([16]byte{}) {
			continue
		}
		if age := rowAge(value.LastSeen, now); !counts.HasReverse || age > counts.OldestAge {
			counts.OldestAge = age
		}
		counts.HasReverse = true
		if !sessionExpired(&value, now) {
			counts.Live[SessionKey{Family: rawKey.Family, Proto: sessionProto(value.Proto)}]++
		}
	}
	if err := it.Err(); err != nil {
		return counts, fmt.Errorf("natmap: nat_conn_table: count: %w", err)
	}
	return counts, nil
}
