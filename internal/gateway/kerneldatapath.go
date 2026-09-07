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

// protoNumber maps a rule's protocol string to the IANA number the datapath's
// key expects. There is no shared constant: the CRD enum is a string for
// readability while the wire format is the numeric value read off the packet,
// and this is the one place the two representations meet.
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

// vipKeysForRule returns the vip_table keys ApplyRule registers for rule, one
// per VIP address, the map being keyed by protocol, port, and address with the
// backend list and Maglev table identical across every VIP a rule owns.
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

// buildMaglevTable builds the ordered backend list and the flattened Maglev
// lookup table Register expects from rule.Backends:
//
//  1. Reject up front when the backend count exceeds the cap. The CRD already
//     bounds it, but a silently truncated array is worse than a clear error.
//  2. Build a Maglev table over the backends, each of which supplies its own
//     key.
//  3. The table returns its backend set sorted by key, and that order becomes
//     each backend's index into the returned slice, and so into the map value's
//     fixed-size array.
//  4. For each slot, resolve the assigned backend and translate it back to its
//     index through a key-to-index map built from the same sorted list.
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

// KernelDatapath is the real Datapath implementation, backed by the map layer
// over a loaded edge program. It assumes the program is already loaded and
// attached to the node's public interface by the time ApplyRule is first
// called; that lifecycle belongs to the attach package and process startup.
type KernelDatapath struct {
	mu       sync.Mutex
	vipTable *edgemap.VIPTable

	// vipKeysByName maps a rule's key to the vip_table keys currently registered
	// for it, so RemoveRule, which receives only a key string, knows what to
	// unregister, and ApplyRule can prune a key the rule dropped since its last
	// apply without the caller having tracked it.
	vipKeysByName map[string][]edgemap.VIPKey
}

// NewKernelDatapath constructs a KernelDatapath and writes encapSrc into the
// encapsulation config once, immediately. encapSrc is this node's plain
// SRv6-reachable address, stable for the life of the process, so nothing per
// rule or per reconcile ever rewrites it. It is never a translation source and
// has no return-path significance.
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

// ApplyRule registers vip_table entries for rule, one per VIP address sharing
// its Maglev table, replacing whatever the rule had registered before and
// pruning any key it no longer owns.
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
			// already owned, the prune below not having run yet, so
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

// ReconcileOrphans removes vip_table entries whose key is not implied by any
// rule in live and was written before cutoff, delegating to the map layer's
// reconcile.
func (d *KernelDatapath) ReconcileOrphans(_ context.Context, live []DesiredRule, cutoff uint64) error {
	liveKeys := make(map[edgemap.VIPKey]struct{})
	for _, rule := range live {
		keys, err := vipKeysForRule(rule)
		if err != nil {
			// A rule with an unsupported protocol was never registered, so
			// it owns no entry to spare here. Skip rather than fail the
			// whole sweep over one bad rule.
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
