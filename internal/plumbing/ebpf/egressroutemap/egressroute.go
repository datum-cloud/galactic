// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// neighborResolveTimeout and neighborResolvePollInterval bound how long
// resolveNeighbor waits for a solicited neighbor entry to resolve. A real
// exchange on a healthy link is well under 100ms, so this is headroom rather
// than an expected wait.
const (
	neighborResolveTimeout      = 2 * time.Second
	neighborResolvePollInterval = 100 * time.Millisecond
)

// neighborSolicitDialTimeout bounds solicitNeighbor's Dial. A UDP dial does not
// block on the network, but this guards the pathological case of an unreachable
// or filtered link.
const neighborSolicitDialTimeout = 200 * time.Millisecond

// egressRouteFamilyINET6 and egressRouteFamilyINET4 mirror the datapath's
// family constants. bpf2go generates no symbol for a #define, so the raw values
// are named once here.
const (
	egressRouteFamilyINET6 = uint8(0)
	egressRouteFamilyINET4 = uint8(1)
)

// egressRouteKeyFixedBits is how many bits of egress_route_key are always
// matched in full ahead of the variable-length address: table_id plus family.
// It must match the datapath's own computation exactly.
const egressRouteKeyFixedBits = 8 * (4 + 1)

// DefaultPrefix is the IPv6 default route Register installs when called with
// it. Defined here rather than imported from internal/plumbing/srv6, which has
// no eBPF dependency today and should not acquire one for a shared constant.
var DefaultPrefix = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}

// EgressRouteTable is the read/write API for egress_route_table. A specific
// destination prefix and the ::/0 default are the same primitive here, unlike
// their netlink counterparts, since a longest-prefix-match trie already gives
// the more specific entry priority.
type EgressRouteTable struct {
	table usidmap.Table
}

// NewEgressRouteTable wraps table as an EgressRouteTable. Production callers
// pass a kernel table over the loaded map; tests pass a fake.
func NewEgressRouteTable(table usidmap.Table) *EgressRouteTable {
	return &EgressRouteTable{table: table}
}

// buildKey composes egress_route_table's longest-prefix-match key for
// (tableID, prefix). The layout must match the datapath's struct
// egress_route_key byte for byte.
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

// sidTo16 returns sid's raw 16 bytes in wire order, or an error if sid is not a
// genuine IPv6 address. SRv6 SIDs are IPv6-only in this architecture.
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

// resolveLinkAndL2Fn is an override point so tests can substitute a fake
// resolver instead of touching the host network stack. Needed because Register
// calls the real netlink functions whether or not the usidmap.Table it was
// given is a fake.
var resolveLinkAndL2Fn = resolveLinkAndL2

// resolveLinkAndL2 resolves sid's immediate next hop: the link plus the
// destination and source MAC a packet must carry to reach it, from netlink and
// the kernel's neighbor cache.
//
// IPv6 resolution does not recurse through an indirect gateway on its own,
// which is why the flattening is needed. It duplicates srv6.resolveNextHop
// rather than calling it because that package already imports this one, so the
// reverse import would be a cycle. Resolving the L2 addresses as well as the
// link is what lets usid_egress avoid resolving them per packet; see struct
// egress_route_value in usid.c.
func resolveLinkAndL2(sid net.IP) (linkIndex int, dmac, smac net.HardwareAddr, err error) {
	routes, err := netlink.RouteGet(sid)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("no route to %s: %w", sid, err)
	}
	if len(routes) == 0 {
		return 0, nil, nil, fmt.Errorf("no route to %s", sid)
	}
	linkIndex = routes[0].LinkIndex
	nextHop := routes[0].Gw
	if nextHop == nil {
		nextHop = sid // gateway itself is on-link
	}

	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("look up link %d: %w", linkIndex, err)
	}
	smac = link.Attrs().HardwareAddr

	dmac, err = resolveNeighbor(linkIndex, nextHop)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w (next-hop for sid %s)", err, sid)
	}
	return linkIndex, dmac, smac, nil
}

// resolveNeighbor returns nextHop's resolved L2 address on linkIndex, actively
// soliciting the kernel to populate it when a passive cache read finds
// nothing.
//
// A cache read alone is not enough. A new pod namespace, or any link that has
// never sent traffic toward nextHop, starts with an empty cache, and installing
// an egress route generates no traffic that would populate it. A same-node next
// hop can otherwise stay unresolved for a pod's entire uptime while a single
// manual ping resolves it instantly.
func resolveNeighbor(linkIndex int, nextHop net.IP) (net.HardwareAddr, error) {
	if mac, err := lookupNeighbor(linkIndex, nextHop); err != nil {
		return nil, err
	} else if mac != nil {
		return mac, nil
	}

	solicitNeighbor(nextHop)

	deadline := time.Now().Add(neighborResolveTimeout)
	for {
		mac, err := lookupNeighbor(linkIndex, nextHop)
		if err != nil {
			return nil, err
		}
		if mac != nil {
			return mac, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no resolved neighbor entry for %s on link %d after soliciting it", nextHop, linkIndex)
		}
		time.Sleep(neighborResolvePollInterval)
	}
}

// solicitNeighbor asks the kernel to resolve nextHop's L2 address the way
// ordinary traffic would, by sending it a packet. Installing an egress route
// generates no traffic of its own, so nothing else does this on Register's
// behalf.
//
// An administrative NeighSet with NUD_NONE and NTF_USE, the documented "mark as
// used, please resolve" signal, does not work here: against a live veth pair
// with an empty cache it parks the entry in NUD_INCOMPLETE and never carries it
// further, while sending a real packet resolves it in well under a
// millisecond.
//
// The destination port needs no listener, and what becomes of the datagram past
// this host's output path is irrelevant. Constructing and writing it is what
// drives the kernel to resolve the neighbor before the packet reaches the wire.
// Errors from Dial and Write are ignored deliberately: resolveNeighbor's poll
// loop is the only judge of whether this worked.
func solicitNeighbor(nextHop net.IP) {
	dialer := &net.Dialer{Timeout: neighborSolicitDialTimeout}
	conn, err := dialer.DialContext(context.Background(), "udp6", net.JoinHostPort(nextHop.String(), "9"))
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck // best-effort solicit; nothing to react to either way
	_, _ = conn.Write([]byte{0})
}

// lookupNeighbor reads linkIndex's IPv6 neighbor cache for nextHop without
// soliciting. It is resolveNeighbor's passive fast path and its poll step once
// a solicit is in flight.
func lookupNeighbor(linkIndex int, nextHop net.IP) (net.HardwareAddr, error) {
	neighs, err := netlink.NeighList(linkIndex, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("list neighbors on link %d: %w", linkIndex, err)
	}
	for _, n := range neighs {
		if n.IP.Equal(nextHop) && len(n.HardwareAddr) == 6 {
			return n.HardwareAddr, nil
		}
	}
	return nil, nil
}

// Register installs or replaces egress_route_table's entry for prefix in Linux
// VRF table tableID, encapsulating toward sid.
//
// It resolves sid's link and L2 addresses here, at registration time, and
// stores them in the entry, because usid_egress cannot resolve them at packet
// time. Register therefore fails when there is no route or no resolvable
// neighbor yet, and a caller iterating candidate SIDs must tolerate that.
func (t *EgressRouteTable) Register(tableID uint32, prefix *net.IPNet, sid net.IP) error {
	key, err := buildKey(tableID, prefix)
	if err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register: %w", err)
	}
	rawSID, err := sidTo16(sid)
	if err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register: %w", err)
	}
	linkIndex, dmac, smac, err := resolveLinkAndL2Fn(sid)
	if err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register: resolve link/L2 for sid %s: %w", sid, err)
	}

	value := prog.UsidEgressRouteValue{Sid: rawSID, LinkIfindex: uint32(linkIndex)}
	copy(value.Dmac[:], dmac)
	copy(value.Smac[:], smac)

	if err := t.table.Put(key, value); err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register table=%d prefix=%s: %w", tableID, prefix, err)
	}
	return nil
}

// RegisterPassThrough installs or replaces egress_route_table's entry for
// prefix in Linux VRF table tableID as a local pass-through. Unlike Register it
// never encapsulates: it exists so this exact prefix wins the longest-prefix
// lookup over a shorter entry, in practice the VRF's ::/0 NAT66 default.
// usid_egress recognises it by link_ifindex == 0 and defers to the kernel
// instead of redirecting.
//
// Callers register their own attachment's IPAM-assigned prefix here at CNI ADD
// time, for every VRF that prefix lives in. Without it, two attachments sharing
// a VRF on one node, with a working connected route between them, have that
// traffic hijacked by the ::/0 default and redirected toward a NAT66 shard
// instead of delivered locally.
//
// Nothing is resolved here, unlike Register: a pass-through entry carries no
// SID and is never encapsulated toward.
func (t *EgressRouteTable) RegisterPassThrough(tableID uint32, prefix *net.IPNet) error {
	key, err := buildKey(tableID, prefix)
	if err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register pass-through: %w", err)
	}
	if err := t.table.Put(key, prog.UsidEgressRouteValue{}); err != nil {
		return fmt.Errorf("egressroutemap: egress_route_table: register pass-through table=%d prefix=%s: %w",
			tableID, prefix, err)
	}
	return nil
}

// Lookup reads egress_route_table's entry for (tableID, prefix) and reports
// whether it exists. This is an exact-match lookup on the key Register and
// Unregister use, not the longest-prefix match usid_egress performs against a
// packet destination, so it serves tests and observability rather than
// answering what a given destination would resolve to.
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

// Unregister removes egress_route_table's entry for (tableID, prefix). An entry
// that is already absent is not an error, matching the other map writers in
// this codebase.
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

// NodeSourceAddress is the read/write API for node_src_addr_table: this node's
// underlay-facing source address, the value usid_egress writes into every outer
// header it pushes.
type NodeSourceAddress struct {
	table usidmap.Table
}

// nodeSourceAddressKey is node_src_addr_table's only valid key --
// BPF_MAP_TYPE_ARRAY, one entry, matching usid.c's own `src_key = 0`.
const nodeSourceAddressKey = uint32(0)

// Set writes this node's source address. Called once at datapath registration
// time rather than per CNI ADD or DEL, since the value is a per-node constant.
//
// addr must be a specified IPv6 address. usid_egress treats an all-zero entry
// as "not configured yet" and fails open rather than encapsulate with a garbage
// source, and an array map has no genuine missing-key state to signal that any
// other way.
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

// Get reads this node's registered source address and reports whether one has
// ever been Set. An unset, all-zero entry reports ok false rather than an
// all-zero address.
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

// PublicUplink is the read/write API for public_uplink_table: this node's
// fabric-uplink next hop. usid_egress redirects a DSR backend's VIP-sourced
// reply there unconditionally, right after apply_vip_xlat rewrites its source,
// bypassing egress_route_table's NAT66 default. Without it such a reply is
// re-translated through a shard and the client discards it.
type PublicUplink struct {
	table usidmap.Table
}

// publicUplinkKey is public_uplink_table's only valid key. The map is a
// one-entry array, matching node_src_addr_table.
const publicUplinkKey = uint32(0)

// Set writes this node's fabric-uplink next hop. linkIndex is the interface to
// redirect out of, and dmac and smac the Ethernet addressing to reach that next
// hop, both exactly 6 bytes. Called once at datapath registration time, the same
// lifecycle as NodeSourceAddress.Set.
//
// linkIndex 0 is rejected: usid_egress reads it as "not configured yet" and
// falls through to egress_route_table rather than redirect out a nonexistent
// interface.
func (p *PublicUplink) Set(linkIndex int, dmac, smac net.HardwareAddr) error {
	if linkIndex == 0 {
		return errors.New("egressroutemap: public_uplink_table: set: linkIndex must not be 0")
	}
	if len(dmac) != 6 || len(smac) != 6 {
		return fmt.Errorf("egressroutemap: public_uplink_table: set: dmac and smac must both be 6 bytes, got %d and %d",
			len(dmac), len(smac))
	}
	value := prog.UsidPublicUplinkValue{LinkIfindex: uint32(linkIndex)}
	copy(value.Dmac[:], dmac)
	copy(value.Smac[:], smac)
	if err := p.table.Put(publicUplinkKey, value); err != nil {
		return fmt.Errorf("egressroutemap: public_uplink_table: set: %w", err)
	}
	return nil
}

// Get reads this node's registered fabric-uplink next hop and reports whether
// one has ever been Set. An unset entry reports ok false.
func (p *PublicUplink) Get() (linkIndex int, dmac, smac net.HardwareAddr, ok bool, err error) {
	var value prog.UsidPublicUplinkValue
	if err := p.table.Lookup(publicUplinkKey, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil, nil, false, nil
		}
		return 0, nil, nil, false, fmt.Errorf("egressroutemap: public_uplink_table: get: %w", err)
	}
	if value.LinkIfindex == 0 {
		return 0, nil, nil, false, nil
	}
	dmac = append(net.HardwareAddr{}, value.Dmac[:]...)
	smac = append(net.HardwareAddr{}, value.Smac[:]...)
	return int(value.LinkIfindex), dmac, smac, true, nil
}
