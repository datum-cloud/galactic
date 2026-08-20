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

// MaxBackends is edgedsr.c's EDGE_MAX_BACKENDS, hand-kept in sync -- bpf2go's
// -type flag generates a Go struct matching struct vip_value's fixed-size
// Backends array, but the #define itself has no BTF representation to
// generate a Go constant from (same reason
// internal/plumbing/ebpf/prog/dropreason.go's constants are hand-kept, not
// generated). Register rejects more backends than this before ever writing
// to the map, rather than letting a silently-truncated Put succeed. Matches
// NetworkRuleSpec.Backends' own +kubebuilder:validation:MaxItems=64
// (go.datum.net/network's rule_types.go) -- edgenat.c's predecessor rule_key
// capped this at 8, silently below the CRD's own advertised limit; closed as
// a side effect of the DSR/Maglev rewrite rather than carried forward
// unexamined.
const MaxBackends = 64

// MaglevTableSize is edgedsr.c's EDGE_MAGLEV_TABLE_SIZE, hand-kept in sync
// for the same reason as MaxBackends. It is the fixed slot count of
// vip_value's own maglev_table array -- every Register call must supply a
// [MaglevTableSize]byte array built from internal/maglev.Table's own
// Backends()/Lookup() (see kerneldatapath.go's buildMaglevBackends), sized
// to exactly this constant, not internal/maglev.Table's own configurable
// Size().
const MaglevTableSize = 1021

// MaxVIPTableEntries is vip_table's own __uint(max_entries, ...) in
// edgedsr.c, hand-kept in sync for the same reason as MaxBackends (a map's
// max_entries has no BTF representation bpf2go could generate a Go constant
// from). internal/gateway's QuotaEnforcer uses this as the hard ceiling
// protecting the shared map's fixed capacity across every tenant on the
// node -- vip_table itself has no notion of "full,"
// bpf_map_update_elem simply starts failing once it is, so this quota exists
// to fail closed at the control-plane admission point instead.
const MaxVIPTableEntries = 4096

// beU16 converts v between host and big-endian ("network") representation
// by a full 2-byte swap -- its own inverse, so this same function is used
// for both directions. Required because edgeprog's generated Go structs
// store a C __be16 field as a plain uint16, and cilium/ebpf's BTF-based
// marshalling writes it using the host's native (little-endian, on every
// architecture this repo targets) byte order with no swap of its own.
func beU16(v uint16) uint16 {
	return v<<8 | v>>8
}

// VIPKey identifies one vip_table row: (proto, VIP port, VIP address). No
// tenant dimension here -- a VIP is globally unique by construction (it's a
// public address), so this key never needs one; see edgedsr.c's struct
// vip_key doc comment.
type VIPKey struct {
	Proto uint8
	VPort uint16
	VIP   netip.Addr
}

// Backend is one VIPEntry load-balancing target: the backend Pod's own
// address/port, plus the SRv6 uSID of the worker node it's reachable
// through -- resolved by the caller (internal/gateway's control plane) the
// same way any other cross-node SRv6 destination is, never parsed from a
// packet. Unchanged from edgenat.c's predecessor Backend type: DSR still
// needs exactly these three fields, it just never rewrites Addr/Port for
// NAT purposes, only carries them through as identifying metadata (see
// edgedsr.c's struct backend doc comment).
type Backend struct {
	Addr netip.Addr
	Port uint16
	USID netip.Addr
}

// VIPEntry is one fully decoded vip_table row.
type VIPEntry struct {
	VIPKey
	Backends []Backend

	// MaglevTable is the precomputed Maglev lookup table this entry was
	// registered with -- MaglevTable[slot] is an index into Backends,
	// sorted in the same order internal/maglev.Table.Backends() returns
	// (see kerneldatapath.go's buildMaglevBackends). Callers reading this
	// back (e.g. diagnostics) must not mutate it.
	MaglevTable [MaglevTableSize]byte

	// Generation is this table's monotonic-clock reading at the time this
	// entry was last written by Register -- see doc.go's "why VIPTable
	// carries a Generation field" section.
	Generation uint64

	// Packets/Bytes/DroppedPackets/LastSeenNs are per-VIP hit counters
	// maintained by the datapath itself (edgedsr.c's vip_stats_table).
	// Packets counts every packet that matched this VIP+port+protocol,
	// regardless of outcome; DroppedPackets is the subset of those the
	// datapath then dropped (count_claimed_drop) -- so DroppedPackets is
	// always <= Packets. LastSeenNs is a CLOCK_MONOTONIC nanosecond
	// timestamp of the most recent matching packet, 0 if none yet.
	//
	// These live in a separate map from the rest of VIPEntry (vip_table
	// itself), keyed identically -- see Register's doc comment for why
	// (issue #361): Register never reads or writes them, so re-registering
	// a VIP (e.g. every controller reconcile pass) can never race, and
	// therefore never lose, the datapath's own increments. A key with no
	// vip_stats_table row yet (a VIP that has never seen a matching packet)
	// reads back as all zero, not an error.
	Packets        uint64
	Bytes          uint64
	DroppedPackets uint64
	LastSeenNs     uint64
}

// VIPTable is the read/write API for vip_table and vip_stats_table
// together -- two separate eBPF maps, keyed identically (VIPKey), that this
// type presents as one logical table (see Register's doc comment for why
// they're split: issue #361). table backs vip_table (config: backend list,
// Maglev lookup table, Generation); stats backs vip_stats_table (the
// datapath's own hit counters -- Register never touches it).
type VIPTable struct {
	table Table
	stats Table
	clock func() uint64
}

// NewVIPTable wraps table (vip_table) and stats (vip_stats_table) as a
// VIPTable. Production callers pass two KernelTables wrapping a loaded
// *edgeprog.EdgedsrObjects's VipTable/VipStatsTable map fields; tests pass
// fake Tables.
func NewVIPTable(table, stats Table) *VIPTable {
	return &VIPTable{table: table, stats: stats, clock: clockFn}
}

// Generation returns a snapshot of this table's monotonic clock. A caller
// intending to call Reconcile must capture this immediately *before*
// listing the NetworkRule CRDs that will become Reconcile's live set.
func (t *VIPTable) Generation() uint64 {
	return t.clock()
}

func toWireKey(key VIPKey) (edgeprog.EdgedsrVipKey, error) {
	if !key.VIP.Is6() || key.VIP.Is4In6() {
		return edgeprog.EdgedsrVipKey{}, fmt.Errorf("VIP %s is not a native IPv6 address (phase 1 is IPv6-only)", key.VIP)
	}
	return edgeprog.EdgedsrVipKey{Proto: key.Proto, Port: beU16(key.VPort), Vip: key.VIP.As16()}, nil
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

// Register writes (or overwrites) the vip_table entry for key, mapping it
// to backends and maglevTable and stamping it with this table's current
// Generation. maglevTable[slot] must be an index into backends (i.e. into
// the same slice, in the same order) -- see kerneldatapath.go's
// buildMaglevBackends for how the caller builds both together from a
// DesiredRule's backend list. Rejects an empty or over-capacity backend
// list before ever writing to the map, per MaxBackends' doc comment.
//
// This is a blind overwrite of vip_table, not a read-modify-write -- same
// issue #361 rationale as edgenat.c's predecessor rule_table.Register: it
// never touches vip_stats_table at all, so it has nothing to race against
// the datapath's own per-packet __sync_fetch_and_add calls into that map.
// Moving the counters to their own map (vip_stats_table, populated lazily
// by the datapath itself, never by this method) closes the race instead of
// narrowing it: nothing this method does can ever discard a concurrent
// datapath increment, because this method has no reason to read or write
// that map.
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
	return nil
}

// Unregister removes the vip_table entry for key, if present, and its
// vip_stats_table counterpart, if any (best-effort past that point -- see
// below). Not an error if either is already absent.
//
// Deleting the stats row too, rather than leaving it behind, keeps
// vip_stats_table from accumulating rows for VIPs that no longer exist:
// unlike vip_table, whose capacity is enforced up front by
// internal/gateway's QuotaEnforcer, nothing else here bounds
// vip_stats_table's own occupancy, and it is a plain BPF_MAP_TYPE_HASH
// (edgedsr.c), not self-evicting the way an LRU map would be. If the stats
// delete fails after the config delete already succeeded, the VIP itself is
// still gone (the caller's Reconcile/RemoveRule sees it as removed); the
// orphaned stats row is a latent leak, not a correctness problem for
// anything reading vip_table, so this reports the error rather than
// silently swallowing it, but does not roll back the config delete to "fix"
// it.
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
	return nil
}

// lookupStats reads vip_stats_table's row for wireKey, defaulting to the
// zero value (a VIP that has never seen a matching packet has no row yet --
// see VIPEntry's doc comment) rather than treating a miss as an error.
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

// Reconcile brings vip_table into agreement with live -- the caller's
// current set of VIPKeys that have a live NetworkRule CRD -- removing every
// vip_table entry whose key is absent from live, *except* an entry whose
// Generation is >= cutoff (it was written after the caller's live snapshot
// was taken, so deleting it could race a fresh Register). See doc.go's "why
// VIPTable carries a Generation field."
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
	return removed, errors.Join(errs...)
}
