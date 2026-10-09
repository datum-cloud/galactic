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

	// vpcMu guards vpcByKey on its own, so a metrics scrape never waits on a
	// rule's map writes under mu.
	vpcMu sync.RWMutex

	// vpcByKey maps each vip_table key this process registered to the VPC of
	// the rule that registered it, for the metrics collector's vpc label. It
	// is in memory only: after a restart it is empty until the first
	// reconcile re-applies every rule.
	vpcByKey map[edgemap.VIPKey]string
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
			edgemap.KernelTable{Map: objs.VipTable}, edgemap.KernelTable{Map: objs.VipStatsTable},
			edgemap.KernelTable{Map: objs.VipAddrTable}, edgemap.KernelTable{Map: objs.VipReturnStatsTable}),
		vipKeysByName: make(map[string][]edgemap.VIPKey),
		vpcByKey:      make(map[edgemap.VIPKey]string),
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

	// Attribute every key, and every key the rule already owns, before any
	// write, so a scrape never lists a new entry without its VPC. A key whose
	// write then fails emits no series, and is forgotten again below.
	d.setVPCs(keys, rule.VPCRef)
	d.setVPCs(d.vipKeysByName[rule.Key], rule.VPCRef)

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
			for _, unwritten := range keys[i:] {
				if !slices.Contains(d.vipKeysByName[rule.Key], unwritten) {
					d.clearVPC(unwritten)
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
		d.clearVPC(old)
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
		d.clearVPC(k)
	}
	delete(d.vipKeysByName, key)
	return nil
}

// setVPCs records vpc as the owner of every key in keys.
func (d *KernelDatapath) setVPCs(keys []edgemap.VIPKey, vpc string) {
	d.vpcMu.Lock()
	defer d.vpcMu.Unlock()
	if d.vpcByKey == nil {
		d.vpcByKey = make(map[edgemap.VIPKey]string)
	}
	for _, k := range keys {
		d.vpcByKey[k] = vpc
	}
}

// clearVPC forgets the owner of key once its vip_table entry is gone.
func (d *KernelDatapath) clearVPC(key edgemap.VIPKey) {
	d.vpcMu.Lock()
	defer d.vpcMu.Unlock()
	delete(d.vpcByKey, key)
}

// VPCAttribution implements edgemetrics.VPCAttribution. Several rules can
// share one VIP address on different ports or protocols, and edge_return counts
// per address, so an address whose rules belong to more than one VPC is left
// out of addrs rather than credited to any one of them.
func (d *KernelDatapath) VPCAttribution() (rules map[edgemap.VIPKey]string, addrs map[netip.Addr]string) {
	d.vpcMu.RLock()
	defer d.vpcMu.RUnlock()

	rules = make(map[edgemap.VIPKey]string, len(d.vpcByKey))
	addrs = make(map[netip.Addr]string, len(d.vpcByKey))
	shared := make(map[netip.Addr]struct{})
	for key, vpc := range d.vpcByKey {
		rules[key] = vpc
		if prev, ok := addrs[key.VIP]; ok && prev != vpc {
			shared[key.VIP] = struct{}{}
		}
		addrs[key.VIP] = vpc
	}
	for addr := range shared {
		delete(addrs, addr)
	}
	return rules, addrs
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
