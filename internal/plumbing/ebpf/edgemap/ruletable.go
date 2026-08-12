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

// MaxBackends is edgenat.c's EDGE_MAX_BACKENDS, hand-kept in sync --
// bpf2go's -type flag generates a Go struct matching struct rule_value's
// fixed-size Backends array, but the #define itself has no BTF
// representation to generate a Go constant from (same reason
// internal/plumbing/ebpf/prog/dropreason.go's constants are hand-kept, not
// generated). Register rejects more backends than this before ever
// writing to the map, rather than letting a silently-truncated Put
// succeed.
const MaxBackends = 8

// MaxRuleTableEntries is rule_table's own __uint(max_entries, ...) in
// edgenat.c, hand-kept in sync for the same reason as MaxBackends (a map's
// max_entries has no BTF representation bpf2go could generate a Go
// constant from). internal/gateway's QuotaEnforcer (Phase E) uses this as
// the hard ceiling protecting the shared map's fixed capacity across every
// tenant on the node -- rule_table itself has no notion of "full,"
// bpf_map_update_elem simply starts failing once it is, so this quota
// exists to fail closed at the control-plane admission point instead.
const MaxRuleTableEntries = 4096

// beU16 converts v between host and big-endian ("network") representation
// by a full 2-byte swap -- its own inverse, so this same function is used
// for both directions. Required because edgeprog's generated Go structs
// store a C __be16 field as a plain uint16, and cilium/ebpf's BTF-based
// marshalling writes it using the host's native (little-endian, on every
// architecture this repo targets) byte order with no swap of its own.
func beU16(v uint16) uint16 {
	return v<<8 | v>>8
}

// RuleKey identifies one rule_table row: (proto, VIP port, VIP address).
// No tenant dimension here -- a VIP is globally unique by construction
// (it's a public address), so this key never needs one; see edgenat.c's
// struct rule_key doc comment.
type RuleKey struct {
	Proto uint8
	VPort uint16
	VIP   netip.Addr
}

// Backend is one RuleEntry load-balancing target: the backend Pod's own
// address/port, plus the SRv6 uSID of the worker node it's reachable
// through -- resolved by the caller (internal/gateway's control plane) the
// same way any other cross-node SRv6 destination is, never parsed from a
// packet. This is the field that replaces the earlier, rejected gwprog
// design's shared per-rule VNI/GeneveIfindex: each backend here can be
// reached through a genuinely different worker node, so the uSID has to
// live per-backend, not per-rule.
type Backend struct {
	Addr netip.Addr
	Port uint16
	USID netip.Addr
}

// RuleEntry is one fully decoded rule_table row.
type RuleEntry struct {
	RuleKey
	Backends []Backend

	// Generation is this table's monotonic-clock reading at the time this
	// entry was last written by Register -- see doc.go's "why RuleTable
	// carries a Generation field" section.
	Generation uint64

	// Packets/Bytes/DroppedPackets/LastSeenNs are per-rule hit counters
	// maintained by the datapath itself (edgenat.c's rule_value, Phase E),
	// backing internal/gateway's QuotaEnforcer/TelemetryEmitter. Packets
	// counts every packet that matched this rule's VIP+port+protocol,
	// regardless of outcome; DroppedPackets is the subset of those the
	// datapath then dropped (count_claimed_drop) -- so DroppedPackets is
	// always <= Packets. LastSeenNs is a CLOCK_MONOTONIC nanosecond
	// timestamp of the most recent matching packet, 0 if none yet.
	//
	// Register preserves these across re-registration (read-modify-write)
	// -- see that method's doc comment for why a naive overwrite would
	// zero them on every controller reconcile pass.
	Packets        uint64
	Bytes          uint64
	DroppedPackets uint64
	LastSeenNs     uint64
}

// RuleTable is the read/write API for rule_table.
type RuleTable struct {
	table Table
	clock func() uint64
}

// NewRuleTable wraps table as a RuleTable. Production callers pass a
// KernelTable wrapping a loaded *edgeprog.EdgenatObjects's RuleTable map;
// tests pass a fake Table.
func NewRuleTable(table Table) *RuleTable {
	return &RuleTable{table: table, clock: clockFn}
}

// Generation returns a snapshot of this table's monotonic clock. A caller
// intending to call Reconcile must capture this immediately *before*
// listing the NetworkRule CRDs that will become Reconcile's live set.
func (t *RuleTable) Generation() uint64 {
	return t.clock()
}

func toWireKey(key RuleKey) (edgeprog.EdgenatRuleKey, error) {
	if !key.VIP.Is6() || key.VIP.Is4In6() {
		return edgeprog.EdgenatRuleKey{}, fmt.Errorf("VIP %s is not a native IPv6 address (phase 1 is IPv6-only)", key.VIP)
	}
	return edgeprog.EdgenatRuleKey{Proto: key.Proto, Port: beU16(key.VPort), Vip: key.VIP.As16()}, nil
}

func toWireBackends(backends []Backend) ([MaxBackends]edgeprog.EdgenatBackend, error) {
	var out [MaxBackends]edgeprog.EdgenatBackend
	for i, b := range backends {
		if !b.Addr.Is6() || b.Addr.Is4In6() {
			return out, fmt.Errorf("backend %d address %s is not a native IPv6 address (phase 1 is IPv6-only)", i, b.Addr)
		}
		if !b.USID.Is6() || b.USID.Is4In6() {
			return out, fmt.Errorf("backend %d uSID %s is not a native IPv6 address", i, b.USID)
		}
		out[i] = edgeprog.EdgenatBackend{Addr: b.Addr.As16(), Port: beU16(b.Port), Usid: b.USID.As16()}
	}
	return out, nil
}

// Register writes (or overwrites) the rule_table entry for key, mapping
// it to backends and stamping it with this table's current Generation.
// Rejects an empty or over-capacity backend list before ever writing to
// the map, per MaxBackends' doc comment.
//
// This is a read-modify-write, not a blind overwrite: it looks up any
// existing entry first and carries its Packets/Bytes/DroppedPackets/
// LastSeenNs counters forward into the new value. Those counters are
// maintained by the datapath itself on every packet (edgenat.c), not by
// this method -- internal/gateway.Engine.Reconcile calls ApplyRule (and
// therefore this method) for every desired rule on *every* reconcile
// pass, not just changed ones (see that method's own doc comment), so a
// naive overwrite would zero a long-lived, healthy rule's counters on
// every controller resync. Same fix as an earlier, rejected design's
// equivalent register method.
func (t *RuleTable) Register(key RuleKey, backends []Backend) error {
	if len(backends) == 0 {
		return fmt.Errorf("edgemap: rule_table: register %+v: at least one backend is required", key)
	}
	if len(backends) > MaxBackends {
		return fmt.Errorf("edgemap: rule_table: register %+v: %d backends exceeds MaxBackends (%d)",
			key, len(backends), MaxBackends)
	}

	wireKey, err := toWireKey(key)
	if err != nil {
		return fmt.Errorf("edgemap: rule_table: register %+v: %w", key, err)
	}
	wireBackends, err := toWireBackends(backends)
	if err != nil {
		return fmt.Errorf("edgemap: rule_table: register %+v: %w", key, err)
	}

	var existing edgeprog.EdgenatRuleValue
	if err := t.table.Lookup(wireKey, &existing); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("edgemap: rule_table: register %+v: look up existing entry: %w", key, err)
	}

	value := edgeprog.EdgenatRuleValue{
		BackendCount:   uint32(len(backends)),
		Backends:       wireBackends,
		Generation:     t.clock(),
		Packets:        existing.Packets,
		Bytes:          existing.Bytes,
		DroppedPackets: existing.DroppedPackets,
		LastSeenNs:     existing.LastSeenNs,
	}
	if err := t.table.Put(wireKey, value); err != nil {
		return fmt.Errorf("edgemap: rule_table: register %+v: %w", key, err)
	}
	return nil
}

// Unregister removes the rule_table entry for key, if present. Not an
// error if already absent.
func (t *RuleTable) Unregister(key RuleKey) error {
	wireKey, err := toWireKey(key)
	if err != nil {
		return fmt.Errorf("edgemap: rule_table: unregister %+v: %w", key, err)
	}
	if err := t.table.Delete(wireKey); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("edgemap: rule_table: unregister %+v: %w", key, err)
	}
	return nil
}

func fromWireValue(key RuleKey, value edgeprog.EdgenatRuleValue) RuleEntry {
	backends := make([]Backend, value.BackendCount)
	for i := range backends {
		wb := value.Backends[i]
		backends[i] = Backend{
			Addr: netip.AddrFrom16(wb.Addr),
			Port: beU16(wb.Port),
			USID: netip.AddrFrom16(wb.Usid),
		}
	}
	return RuleEntry{
		RuleKey:        key,
		Backends:       backends,
		Generation:     value.Generation,
		Packets:        value.Packets,
		Bytes:          value.Bytes,
		DroppedPackets: value.DroppedPackets,
		LastSeenNs:     value.LastSeenNs,
	}
}

// Get reads the rule_table entry for key, reporting whether it exists.
func (t *RuleTable) Get(key RuleKey) (RuleEntry, bool, error) {
	wireKey, err := toWireKey(key)
	if err != nil {
		return RuleEntry{}, false, fmt.Errorf("edgemap: rule_table: get %+v: %w", key, err)
	}

	var value edgeprog.EdgenatRuleValue
	if err := t.table.Lookup(wireKey, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return RuleEntry{}, false, nil
		}
		return RuleEntry{}, false, fmt.Errorf("edgemap: rule_table: get %+v: %w", key, err)
	}
	return fromWireValue(key, value), true, nil
}

// List returns every entry currently in rule_table, in unspecified order.
func (t *RuleTable) List() ([]RuleEntry, error) {
	var (
		entries []RuleEntry
		rawKey  edgeprog.EdgenatRuleKey
		value   edgeprog.EdgenatRuleValue
	)
	it := t.table.Iterate()
	for it.Next(&rawKey, &value) {
		key := RuleKey{Proto: rawKey.Proto, VPort: beU16(rawKey.Port), VIP: netip.AddrFrom16(rawKey.Vip)}
		entries = append(entries, fromWireValue(key, value))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("edgemap: rule_table: list: %w", err)
	}
	return entries, nil
}

// Reconcile brings rule_table into agreement with live -- the caller's
// current set of RuleKeys that have a live NetworkRule CRD -- removing
// every rule_table entry whose key is absent from live, *except* an entry
// whose Generation is >= cutoff (it was written after the caller's live
// snapshot was taken, so deleting it could race a fresh Register). See
// doc.go's "why RuleTable carries a Generation field."
func (t *RuleTable) Reconcile(live map[RuleKey]struct{}, cutoff uint64) (removed []RuleEntry, err error) {
	entries, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("edgemap: rule_table: reconcile: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if _, ok := live[e.RuleKey]; ok {
			continue
		}
		if e.Generation >= cutoff {
			continue
		}
		if err := t.Unregister(e.RuleKey); err != nil {
			errs = append(errs, fmt.Errorf("edgemap: rule_table: reconcile: delete stale entry %+v: %w", e.RuleKey, err))
			continue
		}
		removed = append(removed, e)
	}
	return removed, errors.Join(errs...)
}
