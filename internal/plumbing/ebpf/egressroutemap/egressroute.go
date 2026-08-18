// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// egressRouteFamilyINET6/egressRouteFamilyINET4 mirror usid.c's
// USID_EGRESS_ROUTE_FAMILY_INET6/USID_EGRESS_ROUTE_FAMILY_INET4 --
// bpf2go generates no symbol for a #define, so this package names the raw
// values once here, the same way usid_test.go's own identically-named
// constants do for the datapath's own tests.
const (
	egressRouteFamilyINET6 = uint8(0)
	egressRouteFamilyINET4 = uint8(1)
)

// egressRouteKeyFixedBits is the number of bits egress_route_key's fixed
// (always fully matched) portion occupies ahead of the variable-length
// address bits -- table_id (32) + family (8) -- matching usid.c's own
// `8 * (sizeof(rkey.table_id) + sizeof(rkey.family))` computation exactly.
const egressRouteKeyFixedBits = 8 * (4 + 1)

// DefaultPrefix is the IPv6 default route (::/0) Register installs when
// called with it -- srv6.EgressDefaultRouteAdd's own defaultRoutePrefix,
// reproduced here rather than imported (internal/plumbing/srv6 has no
// eBPF/cilium dependency today and this package does not want to be the
// reason it acquires one just for a shared constant).
var DefaultPrefix = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

// EgressRouteTable is the read/write API for egress_route_table -- the
// TC-BPF replacement for srv6.RouteEgressAdd/RouteEgressDel (a specific
// destination prefix) and srv6.EgressDefaultRouteAdd/EgressDefaultRouteDel
// (prefix == DefaultPrefix); both are the same primitive here, unlike
// their netlink-route counterparts, since a longest-prefix-match trie
// naturally gives a more specific entry priority over a ::/0 one with no
// special-casing needed.
type EgressRouteTable struct {
	table usidmap.Table
}

// NewEgressRouteTable wraps table as an EgressRouteTable. Production
// callers pass a usidmap.KernelTable wrapping a loaded egress_route_table
// map (see OpenPinnedEgressRouteTable); tests pass a fake usidmap.Table.
func NewEgressRouteTable(table usidmap.Table) *EgressRouteTable {
	return &EgressRouteTable{table: table}
}

// buildKey composes egress_route_table's LPM key for (tableID, prefix) --
// see usid.c's struct egress_route_key doc comment for the exact bit
// layout this must match byte-for-byte.
func buildKey(tableID uint32, prefix *net.IPNet) (prog.UsidEgressRouteKey, error) {
	if prefix == nil {
		return prog.UsidEgressRouteKey{}, errors.New("egressroutemap: egress_route_table: prefix is nil")
	}
	ones, bits := prefix.Mask.Size()
	if bits == 0 {
		return prog.UsidEgressRouteKey{}, fmt.Errorf("egressroutemap: egress_route_table: prefix %s has a bad mask", prefix)
	}

	key := prog.UsidEgressRouteKey{
		TableId:   tableID,
		Prefixlen: uint32(egressRouteKeyFixedBits + ones),
	}
	if v4 := prefix.IP.To4(); v4 != nil {
		key.Family = egressRouteFamilyINET4
		copy(key.Addr[:4], v4)
		return key, nil
	}
	v6 := prefix.IP.To16()
	if v6 == nil {
		return prog.UsidEgressRouteKey{}, fmt.Errorf("egressroutemap: egress_route_table: %s is not a valid prefix", prefix)
	}
	key.Family = egressRouteFamilyINET6
	copy(key.Addr[:], v6)
	return key, nil
}

// sidTo16 returns sid's raw 16 bytes in wire order, or an error if sid is
// not a genuine IPv6 address -- SRv6 SIDs are IPv6-only in this
// architecture (matching srv6.RouteEgressAdd's own "gateway must be a
// real SRv6 SID" guard).
func sidTo16(sid net.IP) ([16]byte, error) {
	if sid == nil {
		return [16]byte{}, errors.New("egressroutemap: egress_route_table: sid is nil")
	}
	a, ok := netip.AddrFromSlice(sid)
	if !ok {
		return [16]byte{}, fmt.Errorf("egressroutemap: egress_route_table: %v is not a valid IP address", sid)
	}
	a = a.Unmap()
	if !a.Is6() || a.IsUnspecified() {
		return [16]byte{}, fmt.Errorf(
			"egressroutemap: egress_route_table: %s is not a usable SRv6 SID (must be a specified IPv6 address)", a)
	}
	return a.As16(), nil
}

// Register installs (or replaces) egress_route_table's entry for prefix
// in Linux VRF table tableID, encapsulating toward sid -- the TC-BPF
// replacement for srv6.RouteEgressAdd (a specific prefix) and
// srv6.EgressDefaultRouteAdd (prefix == DefaultPrefix).
//
// Unlike RouteEgressAdd/EgressDefaultRouteAdd, this never needs to
// resolve sid's own link/next-hop (no srv6.resolveNextHop equivalent):
// usid_egress's own bpf_fib_lookup() resolves that fresh, per packet --
// see struct egress_route_value's doc comment in usid.c for why.
func (t *EgressRouteTable) Register(tableID uint32, prefix *net.IPNet, sid net.IP) error {
	key, err := buildKey(tableID, prefix)
	if err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register: %w", err)
	}
	rawSID, err := sidTo16(sid)
	if err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register: %w", err)
	}
	value := prog.UsidEgressRouteValue{Sid: rawSID}
	if err := t.table.Put(key, value); err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register table=%d prefix=%s: %w", tableID, prefix, err)
	}
	return nil
}

// Lookup reads egress_route_table's entry for (tableID, prefix) -- the
// exact entry Register would have installed for that pair -- reporting
// whether it exists. Note this is an exact-match lookup on the same key
// Register/Unregister use, not the longest-prefix-match usid_egress
// itself performs against an arbitrary packet destination; it exists for
// tests and observability, not to answer "what would this destination
// resolve to."
func (t *EgressRouteTable) Lookup(tableID uint32, prefix *net.IPNet) (sid net.IP, ok bool, err error) {
	key, err := buildKey(tableID, prefix)
	if err != nil {
		return nil, false, fmt.Errorf("egressroutemap: egress_route_table: lookup: %w", err)
	}
	var value prog.UsidEgressRouteValue
	if err := t.table.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("egressroutemap: egress_route_table: lookup table=%d prefix=%s: %w",
			tableID, prefix, err)
	}
	sid = make(net.IP, 16)
	copy(sid, value.Sid[:])
	return sid, true, nil
}

// Unregister removes egress_route_table's entry for (tableID, prefix), if
// present. Not an error if already absent, mirroring this codebase's
// other map-writer packages' identical idempotency contract (e.g.
// usidmap.VRFTable.Unregister, vipxlatmap's unregister).
func (t *EgressRouteTable) Unregister(tableID uint32, prefix *net.IPNet) error {
	key, err := buildKey(tableID, prefix)
	if err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: unregister: %w", err)
	}
	if err := t.table.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("egressroutemap: egress_route_table: unregister table=%d prefix=%s: %w", tableID, prefix, err)
	}
	return nil
}

// NodeSourceAddress is the read/write API for node_src_addr_table -- this
// node's own SRv6/underlay-facing source address, the single value
// usid_egress's egress-routing extension writes into every outer header
// it pushes.
type NodeSourceAddress struct {
	table usidmap.Table
}

// nodeSourceAddressKey is node_src_addr_table's only valid key --
// BPF_MAP_TYPE_ARRAY, one entry, matching usid.c's own `src_key = 0`.
const nodeSourceAddressKey = uint32(0)

// Set writes this node's own source address. Called once, at CNI
// datapath registration time (mirroring attachUsidEgress's own
// once-per-node lifecycle), not per CNI ADD/DEL -- see usid.c's own
// node_src_addr_table comment for why a single-entry array, not a field
// on every egress_route_table entry.
//
// addr must be a specified (non-nil, non-unspecified) IPv6 address --
// usid_egress treats an all-zero entry as "not configured yet" and fails
// open rather than encapsulate with a garbage source (BPF_MAP_TYPE_ARRAY
// has no genuine "missing key" state to detect that some other way; see
// that check's own comment in usid.c).
func (n *NodeSourceAddress) Set(addr net.IP) error {
	raw, err := sidTo16(addr) // identical validation: a specified, non-unspecified IPv6 address
	if err != nil {
		return fmt.Errorf("egressroutemap: node_src_addr_table: set: %w", err)
	}
	if err := n.table.Put(nodeSourceAddressKey, raw); err != nil {
		return fmt.Errorf("egressroutemap: node_src_addr_table: set %s: %w", addr, err)
	}
	return nil
}

// Get reads this node's own currently-registered source address,
// reporting whether one has ever been Set (an unset/all-zero entry --
// see Set's own comment for why that's the map's "not configured" state
// -- reports ok=false, not an all-zero net.IP).
func (n *NodeSourceAddress) Get() (addr net.IP, ok bool, err error) {
	var raw [16]byte
	if err := n.table.Lookup(nodeSourceAddressKey, &raw); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("egressroutemap: node_src_addr_table: get: %w", err)
	}
	a, _ := netip.AddrFromSlice(raw[:])
	if !a.IsValid() || a.IsUnspecified() {
		return nil, false, nil
	}
	return net.IP(raw[:]), true, nil
}
