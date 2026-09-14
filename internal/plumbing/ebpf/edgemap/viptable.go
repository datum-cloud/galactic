// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemap

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// MaxBackends mirrors the datapath's own backend cap, hand-kept in sync: the
// generated Go struct matches the fixed-size array, but a C define has no BTF
// representation to generate a constant from. Register rejects more backends
// than this before writing, rather than letting a silently truncated write
// succeed. It matches the CRD's own maximum.
const MaxBackends = 64

// MaglevTableSize mirrors the datapath's Maglev table slot count, hand-kept in
// sync for the same reason as MaxBackends. Every Register call must supply an
// array of exactly this size, not one sized to the Maglev builder's own
// configurable size.
const MaglevTableSize = 1021

// MaxVIPTableEntries mirrors vip_table's own maximum entry count, hand-kept in
// sync for the same reason as MaxBackends. The engine's quota enforcer uses it
// as the hard ceiling protecting the shared map's capacity across every tenant
// on the node: the map itself has no notion of full, updates simply start
// failing once it is, so the quota fails closed at admission instead.
const MaxVIPTableEntries = 4096

// beU16 swaps a uint16 between host and network byte order. A full 2-byte swap
// is its own inverse, so one function serves both directions. Needed because
// the generated Go structs store a big-endian C field as a plain uint16, which
// the marshalling writes in host order with no swap.
func beU16(v uint16) uint16 {
	return v<<8 | v>>8
}

// VIPKey identifies one vip_table row: protocol, VIP port, and VIP address.
// There is no tenant dimension, a VIP being globally unique by construction.
type VIPKey struct {
	Proto uint8
	VPort uint16
	VIP   netip.Addr
}

// Backend is one load-balancing target: the backend pod's address and port,
// plus the SRv6 uSID of the worker node reaching it, resolved by the control
// plane like any other cross-node SRv6 destination and never parsed from a
// packet. The address and port are carried through as identifying metadata and
// never rewritten.
type Backend struct {
	Addr netip.Addr
	Port uint16
	USID netip.Addr
}

// VIPEntry is one fully decoded vip_table row.
type VIPEntry struct {
	VIPKey
	Backends []Backend

	// MaglevTable is the precomputed lookup table this entry was registered
	// with: each slot holds an index into Backends, in the order the Maglev
	// builder returns them. A caller reading it back must not mutate it.
	MaglevTable [MaglevTableSize]byte

	// Generation is this table's monotonic-clock reading when Register last
	// wrote this entry. See the package doc comment.
	Generation uint64

	// Packets, Bytes, DroppedPackets, and LastSeenNs are per-VIP counters
	// maintained by the datapath. Packets counts every packet matching this
	// VIP, port, and protocol whatever the outcome, and DroppedPackets is the
	// subset the datapath then dropped, so it never exceeds Packets. LastSeenNs
	// is a monotonic nanosecond timestamp of the most recent match, 0 if none.
	//
	// They live in a separate map from the rest of the entry, keyed identically,
	// so Register never reads or writes them and re-registering a VIP cannot
	// race, and so lose, the datapath's increments. A key with no stats row yet
	// reads back as all zero rather than an error.
	Packets        uint64
	Bytes          uint64
	DroppedPackets uint64
	LastSeenNs     uint64
}

// ReturnEntry is one vip_addr_table row: a VIP address this node claims return
// traffic for, joined with the counters edge_return keeps for it.
//
// Keyed by address alone, with no port or protocol, because the return program
// matches on the source address alone -- so one ReturnEntry covers every rule
// sharing that VIP, and its counters aggregate across them.
type ReturnEntry struct {
	VIP netip.Addr

	// Generation is this table's monotonic-clock reading when the address was
	// last written, serving the same reconcile cutoff as VIPEntry's.
	Generation uint64

	// Packets, Bytes, DroppedPackets, and LastSeenNs mirror VIPEntry's, for
	// traffic this VIP sourced rather than traffic addressed to it.
	Packets        uint64
	Bytes          uint64
	DroppedPackets uint64
	LastSeenNs     uint64
}

// VIPTable is the read/write API for vip_table, vip_stats_table, and the two
// return-path maps, which this type presents as one logical table. table holds
// the configuration: backend list, Maglev table, and generation. stats holds the
// datapath's counters, which Register never touches. addrs and returnStats are
// the return path's equivalents, keyed by VIP address alone.
//
// The address set is maintained here rather than by a caller because every
// mutation of vip_table already passes through this type: an address is present
// exactly while some rule still uses it, which Register and Unregister can keep
// true between them and no caller has to remember to.
type VIPTable struct {
	table       Table
	stats       Table
	addrs       Table
	returnStats Table
	clock       func() uint64
}

// NewVIPTable wraps the configuration, statistics, and return-path maps as a
// VIPTable. Production callers pass kernel tables over the four loaded maps;
// tests pass fakes.
func NewVIPTable(table, stats, addrs, returnStats Table) *VIPTable {
	return &VIPTable{table: table, stats: stats, addrs: addrs, returnStats: returnStats, clock: clockFn}
}

// Generation returns a snapshot of this table's monotonic clock. A caller
// intending to call Reconcile must read it immediately before listing the CRDs
// that become that call's live set.
func (t *VIPTable) Generation() uint64 {
	return t.clock()
}

func toWireKey(key VIPKey) (edgeprog.EdgedsrVipKey, error) {
	if !key.VIP.Is6() || key.VIP.Is4In6() {
		return edgeprog.EdgedsrVipKey{}, fmt.Errorf("VIP %s is not a native IPv6 address (phase 1 is IPv6-only)", key.VIP)
	}
	return edgeprog.EdgedsrVipKey{Proto: key.Proto, Port: beU16(key.VPort), Vip: key.VIP.As16()}, nil
}

func toWireAddrKey(vip netip.Addr) (edgeprog.EdgedsrVipAddrKey, error) {
	if !vip.Is6() || vip.Is4In6() {
		return edgeprog.EdgedsrVipAddrKey{}, fmt.Errorf(
			"VIP %s is not a native IPv6 address (phase 1 is IPv6-only)", vip)
	}
	return edgeprog.EdgedsrVipAddrKey{Vip: vip.As16()}, nil
}

func toWireBackends(backends []Backend) ([MaxBackends]edgeprog.EdgedsrBackend, error) {
	var out [MaxBackends]edgeprog.EdgedsrBackend
	for i, b := range backends {
		if !b.Addr.Is6() || b.Addr.Is4In6() {
			return out, fmt.Errorf("backend %d address %s is not a native IPv6 address (phase 1 is IPv6-only)", i, b.Addr)
		}
		if !b.USID.Is6() || b.USID.Is4In6() {
			return out, fmt.Errorf("backend %d uSID %s is not a native IPv6 address", i, b.USID)
		}
		out[i] = edgeprog.EdgedsrBackend{Addr: b.Addr.As16(), Port: beU16(b.Port), Usid: b.USID.As16()}
	}
	return out, nil
}

// Register writes, or overwrites, the vip_table entry for key, mapping it to
// backends and maglevTable and stamping it with the current generation. Each
// slot of maglevTable must be an index into backends, in the same order.
// Rejects an empty or over-capacity backend list before writing.
//
// A blind overwrite rather than a read-modify-write, because it never touches
// the statistics map and so has nothing to race against the datapath's
// per-packet increments. Keeping the counters in a map this method has no
// reason to read closes that race rather than narrowing it.
func (t *VIPTable) Register(key VIPKey, backends []Backend, maglevTable [MaglevTableSize]byte) error {
	if len(backends) == 0 {
		return fmt.Errorf("edgemap: vip_table: register %+v: at least one backend is required", key)
	}
	if len(backends) > MaxBackends {
		return fmt.Errorf("edgemap: vip_table: register %+v: %d backends exceeds MaxBackends (%d)",
			key, len(backends), MaxBackends)
	}

	wireKey, err := toWireKey(key)
	if err != nil {
		return fmt.Errorf("edgemap: vip_table: register %+v: %w", key, err)
	}
	wireBackends, err := toWireBackends(backends)
	if err != nil {
		return fmt.Errorf("edgemap: vip_table: register %+v: %w", key, err)
	}

	value := edgeprog.EdgedsrVipValue{
		BackendCount: uint32(len(backends)),
		Backends:     wireBackends,
		MaglevTable:  maglevTable,
		Generation:   t.clock(),
	}
	if err := t.table.Put(wireKey, value); err != nil {
		return fmt.Errorf("edgemap: vip_table: register %+v: %w", key, err)
	}
	if err := t.claimAddr(key.VIP, value.Generation); err != nil {
		return fmt.Errorf("edgemap: vip_table: register %+v: %w", key, err)
	}
	return nil
}

// claimAddr records vip in vip_addr_table, so edge_return forwards traffic this
// node sources from it. Stamped with the same generation as the vip_table entry
// that claimed it, so a crash mid-reconcile leaves both maps guarded by one
// cutoff.
func (t *VIPTable) claimAddr(vip netip.Addr, generation uint64) error {
	wireAddr, err := toWireAddrKey(vip)
	if err != nil {
		return err
	}
	if err := t.addrs.Put(wireAddr, edgeprog.EdgedsrVipAddrValue{Generation: generation}); err != nil {
		return fmt.Errorf("claim %s in vip_addr_table: %w", vip, err)
	}
	return nil
}

// releaseAddr removes vip from vip_addr_table, and its counters with it, once no
// remaining vip_table entry uses that address.
//
// The scan is why this is not a plain delete: several rules can share one VIP
// across different ports or protocols, and removing one of them must not stop
// return traffic for the others. A scan rather than a reference count because
// vip_table is the only durable record of what is registered -- a count held in
// this process would be wrong after the restart Reconcile's cutoff exists to
// survive.
func (t *VIPTable) releaseAddr(vip netip.Addr) error {
	wireAddr, err := toWireAddrKey(vip)
	if err != nil {
		return err
	}

	var (
		rawKey edgeprog.EdgedsrVipKey
		value  edgeprog.EdgedsrVipValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		if netip.AddrFrom16(rawKey.Vip) == vip {
			return nil // still in use by another rule, port, or protocol
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("scan vip_table for remaining users of %s: %w", vip, err)
	}

	if err := t.addrs.Delete(wireAddr); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("release %s from vip_addr_table: %w", vip, err)
	}
	if err := t.returnStats.Delete(wireAddr); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete %s vip_return_stats_table row: %w", vip, err)
	}
	return nil
}

// Unregister removes the vip_table entry for key, if present, and its
// statistics row, if any. Neither being present is not an error.
//
// The statistics row is deleted rather than left behind so that map does not
// accumulate rows for VIPs that no longer exist: unlike vip_table, whose
// capacity the quota enforcer bounds up front, nothing else bounds it, and it
// is a plain hash map rather than a self-evicting one.
//
// If the statistics delete fails after the configuration delete succeeded, the
// VIP is still gone and the orphaned row is a latent leak rather than a
// correctness problem, so the error is reported without rolling back.
func (t *VIPTable) Unregister(key VIPKey) error {
	wireKey, err := toWireKey(key)
	if err != nil {
		return fmt.Errorf("edgemap: vip_table: unregister %+v: %w", key, err)
	}
	if err := t.table.Delete(wireKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("edgemap: vip_table: unregister %+v: %w", key, err)
	}
	if err := t.stats.Delete(wireKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("edgemap: vip_table: unregister %+v: delete vip_stats_table row: %w", key, err)
	}
	if err := t.releaseAddr(key.VIP); err != nil {
		return fmt.Errorf("edgemap: vip_table: unregister %+v: %w", key, err)
	}
	return nil
}

// ListReturn returns every vip_addr_table row joined with its counters, in
// unspecified order. A row with no counters yet reads back as zero rather than
// an error, as with vip_stats_table.
func (t *VIPTable) ListReturn() ([]ReturnEntry, error) {
	var (
		entries []ReturnEntry
		rawKey  edgeprog.EdgedsrVipAddrKey
		value   edgeprog.EdgedsrVipAddrValue
	)
	it := t.addrs.Iterate()
	for it.Next(&rawKey, &value) {
		var stats edgeprog.EdgedsrVipStatsValue
		if err := t.returnStats.Lookup(rawKey, &stats); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("edgemap: vip_addr_table: list: read vip_return_stats_table row: %w", err)
		}
		entries = append(entries, ReturnEntry{
			VIP:            netip.AddrFrom16(rawKey.Vip),
			Generation:     value.Generation,
			Packets:        stats.Packets,
			Bytes:          stats.Bytes,
			DroppedPackets: stats.DroppedPackets,
			LastSeenNs:     stats.LastSeenNs,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("edgemap: vip_addr_table: list: %w", err)
	}
	return entries, nil
}

// lookupStats reads the statistics row for wireKey, defaulting to the zero
// value rather than treating a miss as an error: a VIP that has never seen a
// matching packet has no row yet.
func (t *VIPTable) lookupStats(wireKey edgeprog.EdgedsrVipKey) (edgeprog.EdgedsrVipStatsValue, error) {
	var stats edgeprog.EdgedsrVipStatsValue
	if err := t.stats.Lookup(wireKey, &stats); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return edgeprog.EdgedsrVipStatsValue{}, err
	}
	return stats, nil
}

func fromWireValue(key VIPKey, value edgeprog.EdgedsrVipValue, stats edgeprog.EdgedsrVipStatsValue) VIPEntry {
	backends := make([]Backend, value.BackendCount)
	for i := range backends {
		wb := value.Backends[i]
		backends[i] = Backend{
			Addr: netip.AddrFrom16(wb.Addr),
			Port: beU16(wb.Port),
			USID: netip.AddrFrom16(wb.Usid),
		}
	}
	return VIPEntry{
		VIPKey:         key,
		Backends:       backends,
		MaglevTable:    value.MaglevTable,
		Generation:     value.Generation,
		Packets:        stats.Packets,
		Bytes:          stats.Bytes,
		DroppedPackets: stats.DroppedPackets,
		LastSeenNs:     stats.LastSeenNs,
	}
}

// Get reads the vip_table entry for key (joined with its vip_stats_table
// counterpart, if any), reporting whether the vip_table entry exists.
func (t *VIPTable) Get(key VIPKey) (VIPEntry, bool, error) {
	wireKey, err := toWireKey(key)
	if err != nil {
		return VIPEntry{}, false, fmt.Errorf("edgemap: vip_table: get %+v: %w", key, err)
	}

	var value edgeprog.EdgedsrVipValue
	if err := t.table.Lookup(wireKey, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return VIPEntry{}, false, nil
		}
		return VIPEntry{}, false, fmt.Errorf("edgemap: vip_table: get %+v: %w", key, err)
	}
	stats, err := t.lookupStats(wireKey)
	if err != nil {
		return VIPEntry{}, false, fmt.Errorf("edgemap: vip_table: get %+v: read vip_stats_table row: %w", key, err)
	}
	return fromWireValue(key, value, stats), true, nil
}

// List returns every vip_table entry, joined with its vip_stats_table
// counterpart if any, in unspecified order.
func (t *VIPTable) List() ([]VIPEntry, error) {
	var (
		entries []VIPEntry
		rawKey  edgeprog.EdgedsrVipKey
		value   edgeprog.EdgedsrVipValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		key := VIPKey{Proto: rawKey.Proto, VPort: beU16(rawKey.Port), VIP: netip.AddrFrom16(rawKey.Vip)}
		stats, err := t.lookupStats(rawKey)
		if err != nil {
			return nil, fmt.Errorf("edgemap: vip_table: list: read vip_stats_table row for %+v: %w", key, err)
		}
		entries = append(entries, fromWireValue(key, value, stats))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("edgemap: vip_table: list: %w", err)
	}
	return entries, nil
}

// Reconcile brings vip_table into agreement with live, the caller's current set
// of keys backed by a live NetworkRule, removing every entry whose key is absent
// from live except one whose generation is at or above cutoff, which was written
// after the caller's snapshot and could race a fresh Register.
func (t *VIPTable) Reconcile(live map[VIPKey]struct{}, cutoff uint64) (removed []VIPEntry, err error) {
	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("edgemap: vip_table: reconcile: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if _, ok := live[e.VIPKey]; ok {
			continue
		}
		if e.Generation >= cutoff {
			continue
		}
		if err := t.Unregister(e.VIPKey); err != nil {
			errs = append(errs, fmt.Errorf("edgemap: vip_table: reconcile: delete stale entry %+v: %w", e.VIPKey, err))
			continue
		}
		removed = append(removed, e)
	}
	if err := t.reconcileAddrs(cutoff); err != nil {
		errs = append(errs, err)
	}
	return removed, errors.Join(errs...)
}

// reconcileAddrs prunes vip_addr_table rows no surviving vip_table entry uses.
//
// Unregister already releases an address as its last rule goes, so this only
// catches rows orphaned by a crash between the two deletes -- the same window
// the generation cutoff guards for vip_table itself, applied to the map that
// would otherwise keep forwarding return traffic for a VIP this node no longer
// serves.
func (t *VIPTable) reconcileAddrs(cutoff uint64) error {
	entries, err := t.List()
	if err != nil {
		return fmt.Errorf("edgemap: vip_addr_table: reconcile: %w", err)
	}
	inUse := make(map[netip.Addr]struct{}, len(entries))
	for _, e := range entries {
		inUse[e.VIP] = struct{}{}
	}

	returns, err := t.ListReturn()
	if err != nil {
		return fmt.Errorf("edgemap: vip_addr_table: reconcile: %w", err)
	}

	var errs []error
	for _, r := range returns {
		if _, ok := inUse[r.VIP]; ok {
			continue
		}
		if r.Generation >= cutoff {
			continue
		}
		if err := t.releaseAddr(r.VIP); err != nil {
			errs = append(errs, fmt.Errorf("edgemap: vip_addr_table: reconcile: %w", err))
		}
	}
	return errors.Join(errs...)
}
