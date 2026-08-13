// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// protoNumber maps a NetworkRuleSpec.Protocol string ("tcp"/"udp") to the
// IANA protocol number edgenat.c's rule_key.proto expects. There is no
// generated/shared constant for this: network.datumapis.com/v1alpha1's
// NetworkRuleProtocol enum is a string type for CRD readability, and
// edgeprog's wire format is the numeric IPPROTO_* value edgenat.c already
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

// ruleKeysForRule returns the rule_table keys ApplyRule registers for
// rule -- one per VIPAddress, since edgenat.c's rule_table is keyed by
// (proto, VIP port, VIP address) with the backend list identical across
// every VIP a rule owns.
func ruleKeysForRule(rule DesiredRule) ([]edgemap.RuleKey, error) {
	proto, err := protoNumber(rule.Protocol)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", rule.Key, err)
	}
	keys := make([]edgemap.RuleKey, len(rule.VIPAddresses))
	for i, vip := range rule.VIPAddresses {
		keys[i] = edgemap.RuleKey{Proto: proto, VPort: rule.Port, VIP: vip}
	}
	return keys, nil
}

// KernelDatapath is the real Datapath implementation, backed by
// internal/plumbing/ebpf/edgemap's RuleTable API onto a loaded
// internal/plumbing/ebpf/edgeprog.EdgenatObjects. It assumes the compiled
// program is already loaded and attached to the gateway node's public
// interface by the time ApplyRule is first called — that attach lifecycle
// is internal/plumbing/ebpf/edgeattach's job and cmd/galactic-router's own
// startup sequence's, not this package's. NoopDatapath remains available
// for tests and any caller not yet wired to a loaded program.
type KernelDatapath struct {
	mu        sync.Mutex
	ruleTable *edgemap.RuleTable

	// ruleKeysByName maps a DesiredRule.Key to the rule_table keys
	// currently registered for it, so RemoveRule (which the Datapath
	// interface only passes a bare key string, not the full DesiredRule)
	// knows what to unregister, and so ApplyRule can prune a key a rule
	// dropped since its last apply (e.g. a VIP removed from
	// spec.vipAddresses) without needing the caller to have tracked that
	// itself.
	ruleKeysByName map[string][]edgemap.RuleKey
}

// NewKernelDatapath constructs a KernelDatapath and writes gwAddr into
// gw_config_table once, immediately -- gwAddr is this gateway node's own
// SRv6-reachable address (NetworkGatewayStatus.SRv6Address), stable for
// the life of the process, so there is no per-rule or per-reconcile path
// that ever needs to rewrite it again.
//
// egressSID/masqAddr optionally populate egress_config_table the same
// way, for the egress (masquerade) datapath
// (datum-cloud/enhancements#865). Both must be their zero netip.Addr
// together (a gateway node not offering egress, the common case today —
// design plan §5) or both valid native IPv6 addresses together
// (config.GatewayConfig.Validate already enforces this pairing before
// this constructor is ever called; this is a defensive second check, not
// the primary one). Leaving egress_config_table unwritten is safe: it
// stays zeroed, and edgenat.c's dispatch never matches a packet against
// the zero address (this file's own header comment).
func NewKernelDatapath(objs *edgeprog.EdgenatObjects, gwAddr, egressSID, masqAddr netip.Addr) (*KernelDatapath, error) {
	if !gwAddr.Is6() || gwAddr.Is4In6() {
		return nil, fmt.Errorf("kerneldatapath: gateway address %s is not a native IPv6 address", gwAddr)
	}

	// All validation runs before any map I/O -- including the egress
	// pair's -- so a validation-only failure never touches
	// gw_config_table/egress_config_table at all (matches
	// TestNewKernelDatapath_RejectsIPv4GatewayAddress's own convention of
	// testing address-family validation without a loaded program).
	egressEnabled := egressSID.IsValid() || masqAddr.IsValid()
	if egressEnabled {
		if !egressSID.IsValid() || !masqAddr.IsValid() {
			return nil, errors.New("kerneldatapath: egress SID and masquerade address must both be set, or neither")
		}
		if !egressSID.Is6() || egressSID.Is4In6() {
			return nil, fmt.Errorf("kerneldatapath: egress SID %s is not a native IPv6 address", egressSID)
		}
		if !masqAddr.Is6() || masqAddr.Is4In6() {
			return nil, fmt.Errorf("kerneldatapath: masquerade address %s is not a native IPv6 address", masqAddr)
		}
	}

	if err := objs.GwConfigTable.Put(uint32(0), edgeprog.EdgenatGwConfig{GwAddr: gwAddr.As16()}); err != nil {
		return nil, fmt.Errorf("kerneldatapath: populate gw_config_table: %w", err)
	}

	if egressEnabled {
		egressCfg := edgeprog.EdgenatEgressConfig{EgressSid: egressSID.As16(), MasqAddr: masqAddr.As16()}
		if err := objs.EgressConfigTable.Put(uint32(0), egressCfg); err != nil {
			return nil, fmt.Errorf("kerneldatapath: populate egress_config_table: %w", err)
		}
	}

	return &KernelDatapath{
		ruleTable:      edgemap.NewRuleTable(edgemap.KernelTable{Map: objs.RuleTable}),
		ruleKeysByName: make(map[string][]edgemap.RuleKey),
	}, nil
}

// ApplyRule registers rule_table entries for rule (one per VIPAddress,
// sharing rule.Backends), replacing whatever this rule had registered
// previously and pruning any key it no longer owns.
func (d *KernelDatapath) ApplyRule(_ context.Context, rule DesiredRule) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	keys, err := ruleKeysForRule(rule)
	if err != nil {
		return err
	}

	backends := make([]edgemap.Backend, len(rule.Backends))
	for i, b := range rule.Backends {
		backends[i] = edgemap.Backend{Addr: b.Address, Port: b.Port, USID: b.USID}
	}

	for i, key := range keys {
		if err := d.ruleTable.Register(key, backends); err != nil {
			// Record the keys that did land, alongside the ones this rule
			// already owned (the prune below has not run yet), so
			// RemoveRule can still find every live entry.
			for _, written := range keys[:i] {
				if !slices.Contains(d.ruleKeysByName[rule.Key], written) {
					d.ruleKeysByName[rule.Key] = append(d.ruleKeysByName[rule.Key], written)
				}
			}
			return fmt.Errorf("kerneldatapath: apply rule %s: %w", rule.Key, err)
		}
	}

	// Prune keys this rule owned before but no longer does (e.g. a VIP
	// removed from spec.vipAddresses on this reconcile).
	stillOwned := make(map[edgemap.RuleKey]struct{}, len(keys))
	for _, k := range keys {
		stillOwned[k] = struct{}{}
	}
	for _, old := range d.ruleKeysByName[rule.Key] {
		if _, ok := stillOwned[old]; ok {
			continue
		}
		if err := d.ruleTable.Unregister(old); err != nil {
			return fmt.Errorf("kerneldatapath: apply rule %s: prune dropped key %+v: %w", rule.Key, old, err)
		}
	}

	d.ruleKeysByName[rule.Key] = keys
	return nil
}

// RemoveRule unregisters every rule_table entry key previously owned.
func (d *KernelDatapath) RemoveRule(_ context.Context, key string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, k := range d.ruleKeysByName[key] {
		if err := d.ruleTable.Unregister(k); err != nil {
			return fmt.Errorf("kerneldatapath: remove rule %s: %w", key, err)
		}
	}
	delete(d.ruleKeysByName, key)
	return nil
}

// Generation returns rule_table's own monotonic-clock snapshot.
func (d *KernelDatapath) Generation() uint64 {
	return d.ruleTable.Generation()
}

// ReconcileOrphans removes rule_table entries whose key is not implied by
// any rule in live and was written before cutoff -- see
// edgemap.RuleTable.Reconcile's identical contract, which this delegates
// to directly.
func (d *KernelDatapath) ReconcileOrphans(_ context.Context, live []DesiredRule, cutoff uint64) error {
	liveKeys := make(map[edgemap.RuleKey]struct{})
	for _, rule := range live {
		keys, err := ruleKeysForRule(rule)
		if err != nil {
			// A rule with an unsupported protocol never got registered
			// by ApplyRule in the first place, so it can't own any
			// rule_table entry to spare here either; skip rather than
			// fail the whole orphan sweep over one bad rule.
			continue
		}
		for _, k := range keys {
			liveKeys[k] = struct{}{}
		}
	}

	if _, err := d.ruleTable.Reconcile(liveKeys, cutoff); err != nil {
		return fmt.Errorf("kerneldatapath: reconcile orphans: %w", err)
	}
	return nil
}

var _ Datapath = (*KernelDatapath)(nil)
