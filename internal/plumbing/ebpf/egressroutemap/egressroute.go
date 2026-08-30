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

// neighborResolveTimeout/neighborResolvePollInterval bound how long
// resolveNeighbor will wait for a solicited neighbor entry to resolve --
// see that function's own doc comment for why an active solicit is
// needed at all. Real ND round-trips on a healthy fabric link are
// sub-100ms; this budget is generous headroom above that, not an
// expected steady-state wait.
const (
	neighborResolveTimeout      = 2 * time.Second
	neighborResolvePollInterval = 100 * time.Millisecond
)

// neighborSolicitDialTimeout bounds solicitNeighbor's own Dial -- a plain
// UDP dial doesn't block on the network, but this still guards against
// the pathological case (an unreachable or filtered link) rather than
// trust that indefinitely.
const neighborSolicitDialTimeout = 200 * time.Millisecond

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

// resolveLinkAndL2Fn is a package-level override point so tests can
// substitute a fake resolver instead of touching the real host network
// stack -- the same pattern internal/plumbing/ebpf/attach's own
// routeListFn/linkByIndexFn vars establish, needed here because Register
// otherwise always calls the real netlink functions below regardless of
// whether the usidmap.Table it was given is itself a fake.
var resolveLinkAndL2Fn = resolveLinkAndL2

// resolveLinkAndL2 resolves sid's real, immediate next-hop -- the exact
// link plus the concrete L2 (destination and source MAC) address a
// packet must carry to actually reach it -- via netlink.RouteGet and the
// kernel's own already-populated neighbor cache.
//
// This mirrors srv6.resolveNextHop's own job (and, for the exact same
// reason: IPv6 route installation/resolution does not recurse through an
// indirect gateway on its own), but cannot simply call it: this package
// is already imported by internal/plumbing/srv6 (for pinDir/
// attach.ResolveInterfaces), so the reverse import would be a cycle.
// Resolving the L2 addresses too, not just the link/next-hop, is new
// here relative to that function -- see struct egress_route_value's own
// doc comment in usid.c for why usid_egress needs them precomputed
// rather than resolving them itself at packet-processing time.
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

// resolveNeighbor returns nextHop's resolved L2 address on linkIndex,
// actively soliciting the kernel to populate it first if a passive read
// of the neighbor cache doesn't already have one.
//
// A cache read alone is not enough: a brand-new pod netns (or any link
// that has simply never sent traffic toward nextHop) starts with an
// empty neighbor cache, and installing an SRv6 egress route generates no
// traffic of its own that would populate it -- a same-node SID next-hop's
// egress route can otherwise fail to resolve for a gateway pod's entire
// uptime, restarts included, purely because nothing ever asks the kernel
// to actually solicit it; a single manual ping resolves it instantly. See
// solicitNeighbor's own doc comment for how the solicit itself is done.
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

// solicitNeighbor asks the kernel to resolve nextHop's L2 address the
// same way any ordinary traffic toward it would: by actually sending it
// a packet. Installing an SRv6 egress route generates no traffic of its
// own (resolveNeighbor's own doc comment), so nothing else will ever do
// this on Register's behalf.
//
// An administrative netlink.NeighSet(NUD_NONE, NTF_USE) -- the "mark as
// used, please resolve" signal without ever constructing a real packet --
// looked like the right tool here (it's the documented kernel mechanism,
// and the technique Cilium's own neighbor-discovery code uses elsewhere),
// but did not hold up: verified against a live veth pair with an empty
// cache, it reliably parks the entry in NUD_INCOMPLETE and never carries
// it further, while sending the peer an actual packet resolves it in well
// under a millisecond every time. This is the version that was actually
// verified to work, not the one that merely looked like it should.
//
// The destination port needs no listener and whatever becomes of the
// datagram past this host's own output path is irrelevant -- constructing
// and writing it is what drives the kernel to resolve (or refresh)
// nextHop's neighbor entry before the packet ever reaches the wire, which
// is the only part this function is here for. Every error from Dial or
// Write is intentionally ignored: resolveNeighbor's own poll loop is the
// sole judge of whether this worked.
func solicitNeighbor(nextHop net.IP) {
	dialer := &net.Dialer{Timeout: neighborSolicitDialTimeout}
	conn, err := dialer.DialContext(context.Background(), "udp6", net.JoinHostPort(nextHop.String(), "9"))
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck // best-effort solicit; nothing to react to either way
	_, _ = conn.Write([]byte{0})
}

// lookupNeighbor reads linkIndex's current IPv6 neighbor cache for
// nextHop, without soliciting -- resolveNeighbor's passive fast path,
// and its own poll step once a solicit is in flight.
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

// Register installs (or replaces) egress_route_table's entry for prefix
// in Linux VRF table tableID, encapsulating toward sid -- the TC-BPF
// replacement for srv6.RouteEgressAdd (a specific prefix) and
// srv6.EgressDefaultRouteAdd (prefix == DefaultPrefix).
//
// Resolves sid's own link and L2 (dmac/smac) information at registration
// time via resolveLinkAndL2, storing all of it in the installed entry --
// see struct egress_route_value's own doc comment in usid.c for why
// usid_egress cannot resolve this itself, at packet-processing time, the
// way it originally did. This means Register can fail the same way
// srv6.RouteEgressAdd's own pre-TC-BPF implementation could (no route yet,
// no resolved neighbor yet) -- callers that iterate multiple candidate
// SIDs (e.g. EgressDefaultRouteAdd's own shard-SID list) must expect and
// tolerate that.
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

// RegisterPassThrough installs (or replaces) egress_route_table's entry
// for prefix in Linux VRF table tableID as a local pass-through: unlike
// Register, this never encapsulates -- it exists purely so this exact
// prefix wins the LPM lookup over a shorter, less specific entry (in
// practice, always the tenant VRF's own ::/0 NAT66 default installed by
// Register(tableID, DefaultPrefix, ...)), and usid_egress recognizes it
// via link_ifindex == 0 (struct egress_route_value's own doc comment in
// usid.c) and defers to the kernel instead of redirecting.
//
// Callers register their own attachment's IPAM-assigned prefix here, at
// CNI ADD time, for every VRF that prefix lives in. Without this, two
// attachments sharing one VRF on the same node -- with a perfectly good
// kernel connected route already routing between them -- have that
// traffic silently hijacked by the VRF's own ::/0 default and redirected
// toward a NAT66 shard SID instead of ever being delivered locally: found
// live in containerlab's ns30 fixture (two attachments, one VPC, one
// node), the same class of bug as the multicast/link-local carve-out in
// usid_egress, just for ordinary same-VRF unicast peers instead of NDP.
//
// No sid/link/L2 resolution happens here (contrast Register) -- a
// pass-through entry carries no SID and is never encapsulated toward, so
// there is nothing to resolve.
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

// PublicUplink is the read/write API for public_uplink_table -- this
// node's own fabric-uplink interface's real, physical next hop.
// usid_egress redirects a DSR backend's VIP-sourced reply here
// unconditionally, immediately after apply_vip_xlat rewrites its source,
// bypassing egress_route_table's own NAT66 default entirely -- see
// struct public_uplink_value's own doc comment in usid.c for the full
// mechanism and the real bug (a DSR reply silently re-SNAT'd through a
// NAT66 shard, the client discarding it as unrecognized) this closes.
type PublicUplink struct {
	table usidmap.Table
}

// publicUplinkKey is public_uplink_table's only valid key --
// BPF_MAP_TYPE_ARRAY, one entry, matching node_src_addr_table's identical
// convention.
const publicUplinkKey = uint32(0)

// Set writes this node's own fabric-uplink next hop: linkIndex is the
// interface to redirect out, dmac/smac the Ethernet addressing needed to
// actually reach that next hop (both exactly 6 bytes). Called once, at
// CNI datapath registration time, the same lifecycle as
// NodeSourceAddress.Set.
//
// linkIndex == 0 is rejected: usid_egress treats it as "not configured
// yet" and fails open (falling through to egress_route_table) rather
// than redirect out a nonexistent interface -- see this map's own
// link_ifindex == 0 sentinel convention (also used, for an unrelated
// purpose, by egress_route_table's own pass-through entries).
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

// Get reads this node's own currently-registered fabric-uplink next hop,
// reporting whether one has ever been Set (an unset/link_ifindex==0
// entry -- see Set's own comment -- reports ok=false).
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
