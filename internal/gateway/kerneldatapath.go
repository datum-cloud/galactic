// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"go.datum.net/galactic/internal/maglev"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// protoNumber maps a NetworkRuleSpec.Protocol string ("tcp"/"udp") to the
// IANA protocol number edgedsr.c's vip_key.proto expects. There is no
// generated/shared constant for this: network.datumapis.com/v1alpha1's
// NetworkRuleProtocol enum is a string type for CRD readability, and
// edgeprog's wire format is the numeric IPPROTO_* value edgedsr.c already
// reads directly off the packet — this is the one place those two
// representations need to be reconciled.
func protoNumber(protocol string) (uint8, error) {
	switch protocol {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	default:
		return 0, fmt.Errorf("kerneldatapath: unsupported protocol %q (want \"tcp\" or \"udp\")", protocol)
	}
}

// vipKeysForRule returns the vip_table keys ApplyRule registers for rule --
// one per VIPAddress, since edgedsr.c's vip_table is keyed by (proto, VIP
// port, VIP address) with the backend list and Maglev table identical
// across every VIP a rule owns.
func vipKeysForRule(rule DesiredRule) ([]edgemap.VIPKey, error) {
	proto, err := protoNumber(rule.Protocol)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.Key, err)
	}
	keys := make([]edgemap.VIPKey, len(rule.VIPAddresses))
	for i, vip := range rule.VIPAddresses {
		keys[i] = edgemap.VIPKey{Proto: proto, VPort: rule.Port, VIP: vip}
	}
	return keys, nil
}

// buildMaglevTable builds the ordered backend list and flattened Maglev
// lookup table Register expects from rule.Backends, via
// internal/maglev.Table:
//
//  1. Reject up front if rule.Backends exceeds edgemap.MaxBackends -- this
//     shouldn't happen given NetworkRuleSpec.Backends' own CRD
//     MaxItems=64, but a silently truncated or overflowed backend array is
//     worse than a clear error here.
//  2. Build a maglev.Table over rule.Backends (each DesiredBackend already
//     implements maglev.Backend via its Key() method — see that method's
//     doc comment for the address:port convention chosen).
//  3. table.Backends() returns the backend set sorted by Key(); that sort
//     order becomes each backend's index into the returned backends slice
//     (and therefore into vip_value's own fixed-size Backends array).
//  4. For each of the table's EDGE_MAGLEV_TABLE_SIZE slots, table.Lookup
//     resolves the assigned backend, translated back to its index via a
//     Key()->index map built from the same sorted list in the previous
//     step.
func buildMaglevTable(rule DesiredRule) ([]edgemap.Backend, [edgemap.MaglevTableSize]byte, error) {
	var maglevTable [edgemap.MaglevTableSize]byte

	if len(rule.Backends) > edgemap.MaxBackends {
		return nil, maglevTable, fmt.Errorf(
			"kerneldatapath: rule %s: %d backends exceeds MaxBackends (%d)",
			rule.Key, len(rule.Backends), edgemap.MaxBackends)
	}

	candidates := make([]maglev.Backend, len(rule.Backends))
	for i, b := range rule.Backends {
		candidates[i] = b
	}

	table, err := maglev.New(candidates, edgemap.MaglevTableSize)
	if err != nil {
		return nil, maglevTable, fmt.Errorf("kerneldatapath: rule %s: build maglev table: %w", rule.Key, err)
	}

	sorted := table.Backends()
	backends := make([]edgemap.Backend, len(sorted))
	indexByKey := make(map[string]int, len(sorted))
	for i, b := range sorted {
		db := b.(DesiredBackend) // every candidate above was built from a DesiredBackend
		backends[i] = edgemap.Backend{Addr: db.Address, Port: db.Port, USID: db.USID}
		indexByKey[b.Key()] = i
	}

	for slot := range maglevTable {
		b := table.Lookup(uint64(slot))
		maglevTable[slot] = byte(indexByKey[b.Key()])
	}

	return backends, maglevTable, nil
}

// KernelDatapath is the real Datapath implementation, backed by
// internal/plumbing/ebpf/edgemap's VIPTable API onto a loaded
// internal/plumbing/ebpf/edgeprog.EdgedsrObjects. It assumes the compiled
// program is already loaded and attached to the gateway node's public
// interface by the time ApplyRule is first called — that attach lifecycle
// is internal/plumbing/ebpf/edgeattach's job and cmd/galactic-gateway's own
// startup sequence's, not this package's. NoopDatapath remains available
// for tests and any caller not yet wired to a loaded program.
type KernelDatapath struct {
	mu       sync.Mutex
	vipTable *edgemap.VIPTable

	// vipKeysByName maps a DesiredRule.Key to the vip_table keys currently
	// registered for it, so RemoveRule (which the Datapath interface only
	// passes a bare key string, not the full DesiredRule) knows what to
	// unregister, and so ApplyRule can prune a key a rule dropped since
	// its last apply (e.g. a VIP removed from spec.vipAddresses) without
	// needing the caller to have tracked that itself.
	vipKeysByName map[string][]edgemap.VIPKey
}

// NewKernelDatapath constructs a KernelDatapath and writes encapSrc into
// encap_config_table once, immediately -- encapSrc is this gateway node's
// own plain SRv6-reachable address (NetworkGatewayStatus.SRv6Address),
// stable for the life of the process, so there is no per-rule or
// per-reconcile path that ever needs to rewrite it again. Unlike the
// Full-NAT predecessor's gw_config (gwAddr), this is never a NAT/SNAT
// source and never needs to match anything on a return path -- DSR has no
// return path through this node at all (see edgedsr.c's own header
// comment).
func NewKernelDatapath(objs *edgeprog.EdgedsrObjects, encapSrc netip.Addr) (*KernelDatapath, error) {
	if !encapSrc.Is6() || encapSrc.Is4In6() {
		return nil, fmt.Errorf("kerneldatapath: encap source address %s is not a native IPv6 address", encapSrc)
	}

	if err := objs.EncapConfigTable.Put(uint32(0), edgeprog.EdgedsrEncapConfig{EncapSrc: encapSrc.As16()}); err != nil {
		return nil, fmt.Errorf("kerneldatapath: populate encap_config_table: %w", err)
	}

	return &KernelDatapath{
		vipTable: edgemap.NewVIPTable(
			edgemap.KernelTable{Map: objs.VipTable}, edgemap.KernelTable{Map: objs.VipStatsTable}),
		vipKeysByName: make(map[string][]edgemap.VIPKey),
	}, nil
}

// ApplyRule registers vip_table entries for rule (one per VIPAddress,
// sharing rule.Backends' Maglev table), replacing whatever this rule had
// registered previously and pruning any key it no longer owns.
func (d *KernelDatapath) ApplyRule(_ context.Context, rule DesiredRule) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	keys, err := vipKeysForRule(rule)
	if err != nil {
		return err
	}

	backends, maglevTable, err := buildMaglevTable(rule)
	if err != nil {
		return err
	}

	for i, key := range keys {
		if err := d.vipTable.Register(key, backends, maglevTable); err != nil {
			// Record the keys that did land, alongside the ones this rule
			// already owned (the prune below has not run yet), so
			// RemoveRule can still find every live entry.
			for _, written := range keys[:i] {
				if !slices.Contains(d.vipKeysByName[rule.Key], written) {
					d.vipKeysByName[rule.Key] = append(d.vipKeysByName[rule.Key], written)
				}
			}
			return fmt.Errorf("kerneldatapath: apply rule %s: %w", rule.Key, err)
		}
	}

	// Prune keys this rule owned before but no longer does (e.g. a VIP
	// removed from spec.vipAddresses on this reconcile).
	stillOwned := make(map[edgemap.VIPKey]struct{}, len(keys))
	for _, k := range keys {
		stillOwned[k] = struct{}{}
	}
	for _, old := range d.vipKeysByName[rule.Key] {
		if _, ok := stillOwned[old]; ok {
			continue
		}
		if err := d.vipTable.Unregister(old); err != nil {
			return fmt.Errorf("kerneldatapath: apply rule %s: prune dropped key %+v: %w", rule.Key, old, err)
		}
	}

	d.vipKeysByName[rule.Key] = keys
	return nil
}

// RemoveRule unregisters every vip_table entry key previously owned.
func (d *KernelDatapath) RemoveRule(_ context.Context, key string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, k := range d.vipKeysByName[key] {
		if err := d.vipTable.Unregister(k); err != nil {
			return fmt.Errorf("kerneldatapath: remove rule %s: %w", key, err)
		}
	}
	delete(d.vipKeysByName, key)
	return nil
}

// Generation returns vip_table's own monotonic-clock snapshot.
func (d *KernelDatapath) Generation() uint64 {
	return d.vipTable.Generation()
}

// ReconcileOrphans removes vip_table entries whose key is not implied by
// any rule in live and was written before cutoff -- see
// edgemap.VIPTable.Reconcile's identical contract, which this delegates to
// directly.
func (d *KernelDatapath) ReconcileOrphans(_ context.Context, live []DesiredRule, cutoff uint64) error {
	liveKeys := make(map[edgemap.VIPKey]struct{})
	for _, rule := range live {
		keys, err := vipKeysForRule(rule)
		if err != nil {
			// A rule with an unsupported protocol never got registered
			// by ApplyRule in the first place, so it can't own any
			// vip_table entry to spare here either; skip rather than
			// fail the whole orphan sweep over one bad rule.
			continue
		}
		for _, k := range keys {
			liveKeys[k] = struct{}{}
		}
	}

	if _, err := d.vipTable.Reconcile(liveKeys, cutoff); err != nil {
		return fmt.Errorf("kerneldatapath: reconcile orphans: %w", err)
	}
	return nil
}

var _ Datapath = (*KernelDatapath)(nil)
