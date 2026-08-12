// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"sync"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
)

// Default limits for NodeQuotaEnforcer. Both are coarse, node-level
// admission caps, not bandwidth or conntrack rate limits -- see that
// type's doc comment for why the latter is deliberately out of scope
// here.
const (
	// DefaultMaxRulesPerTenant bounds how many NetworkRules a single
	// VPCRef may have registered on one gateway node at once. A
	// NetworkRule may carry up to 8 VIPAddresses (network.datumapis.com/
	// v1alpha1's NetworkRuleSpec.VIPAddresses MaxItems), so this also
	// bounds one tenant's worst-case rule_table footprint to
	// DefaultMaxRulesPerTenant*8 entries.
	DefaultMaxRulesPerTenant = 64

	// DefaultMaxRuleTableEntries is the node-wide ceiling across every
	// tenant, defaulting to edgemap.MaxRuleTableEntries (rule_table's own
	// map capacity) -- once desired state would fill the map,
	// bpf_map_update_elem starts failing mid-reconcile with no clean way
	// to roll back a partial apply, so this must be enforced before
	// ApplyRule is ever called, at CheckAndReserve time.
	DefaultMaxRuleTableEntries = edgemap.MaxRuleTableEntries
)

// NodeQuotaEnforcer is a real (not stubbed) QuotaEnforcer implementation,
// enforcing two coarse, node-level admission caps entirely from
// control-plane state Engine already holds — no eBPF map read required:
//
//  1. MaxRulesPerTenant: no single VPCRef may register more than this many
//     NetworkRules on this gateway node at once.
//  2. MaxRuleTableEntries: the total rule_table rows every tenant's rules
//     would occupy together (one row per VIPAddress, see
//     kerneldatapath.go's ruleKeysForRule) may not exceed rule_table's own
//     fixed map capacity.
//
// What this deliberately does NOT do: per-flow or per-tenant conntrack
// (conn_table) rate limiting. conn_table's key carries no tenant
// dimension (design plan decision #1 — a VIP is globally unique, so
// conn_table doesn't need one either), so there is no cheap way to
// attribute an individual flow back to a tenant without adding a field
// that changes the packet-path key layout; and a meaningful bandwidth/
// packet-rate quota needs a time-windowed rate, not the cumulative,
// never-reset Packets/Bytes counters rule_table carries (a long-lived,
// healthy, popular rule will always eventually cross any static
// cumulative threshold — that isn't misbehavior, that's success). Real
// rate-based enforcement needs live traffic data to calibrate sensible
// thresholds against, which is exactly what the design plan's Phase D
// (validated live, not just manifests) was meant to provide before this
// phase built on top of it — see docs/agents/ARCHITECTURE.md and the
// design plan's own Phase E note. This type is the enforceable subset
// buildable without that data.
type NodeQuotaEnforcer struct {
	mu sync.Mutex

	maxRulesPerTenant   int
	maxRuleTableEntries int

	// tenantRuleCount/totalEntries are the enforcer's own bookkeeping of
	// what it has reserved — not read back from rule_table itself, so
	// CheckAndReserve/Release stay correct even before ApplyRule has run
	// (a new rule has no rule_table row yet to read counters from).
	tenantRuleCount map[string]int
	ruleTenant      map[string]string
	ruleEntries     map[string]int
	totalEntries    int
}

// NewNodeQuotaEnforcer returns a NodeQuotaEnforcer with the given limits.
// Use DefaultMaxRulesPerTenant/DefaultMaxRuleTableEntries for production
// defaults.
func NewNodeQuotaEnforcer(maxRulesPerTenant, maxRuleTableEntries int) *NodeQuotaEnforcer {
	return &NodeQuotaEnforcer{
		maxRulesPerTenant:   maxRulesPerTenant,
		maxRuleTableEntries: maxRuleTableEntries,
		tenantRuleCount:     make(map[string]int),
		ruleTenant:          make(map[string]string),
		ruleEntries:         make(map[string]int),
	}
}

// CheckAndReserve reports whether rule fits within both limits and, if so,
// reserves its rule_table footprint. Idempotent for a rule.Key already
// reserved: re-checking (or changing) an already-active rule's VIP count
// never double-counts it against either limit — required because
// Engine.Reconcile calls this for every desired rule on every reconcile
// pass, not just new ones (see Engine.Reconcile's own doc comment).
func (e *NodeQuotaEnforcer) CheckAndReserve(_ context.Context, rule DesiredRule) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	entries := len(rule.VIPAddresses)
	if entries == 0 {
		entries = 1 // defensive: a rule always occupies at least one row
	}

	prevEntries, alreadyReserved := e.ruleEntries[rule.Key]
	prevTenant := e.ruleTenant[rule.Key]

	// Compute what the tenant's rule count and the node total would be if
	// this reservation is accepted, without mutating state yet.
	tenantCount := e.tenantRuleCount[rule.VPCRef]
	if !alreadyReserved {
		tenantCount++
	} else if prevTenant != rule.VPCRef {
		// VPCRef changed for an existing rule.Key -- shouldn't happen in
		// practice (NetworkRuleSpec.VPCRef is not mutated in place by any
		// caller in this codebase), but guard against under/over-counting
		// either tenant bucket if it ever does.
		tenantCount++
	}
	if tenantCount > e.maxRulesPerTenant {
		return false, nil
	}

	projectedTotal := e.totalEntries - prevEntries + entries
	if projectedTotal > e.maxRuleTableEntries {
		return false, nil
	}

	// Accepted: commit the reservation.
	if alreadyReserved && prevTenant != rule.VPCRef {
		e.tenantRuleCount[prevTenant]--
		if e.tenantRuleCount[prevTenant] <= 0 {
			delete(e.tenantRuleCount, prevTenant)
		}
	}
	if !alreadyReserved || prevTenant != rule.VPCRef {
		e.tenantRuleCount[rule.VPCRef] = tenantCount
	}
	e.ruleTenant[rule.Key] = rule.VPCRef
	e.ruleEntries[rule.Key] = entries
	e.totalEntries = projectedTotal
	return true, nil
}

// Release frees the reservation held for key, if any. Not an error if key
// was never reserved (e.g. CheckAndReserve denied it, or it was never
// called for this key at all).
func (e *NodeQuotaEnforcer) Release(_ context.Context, key string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	entries, ok := e.ruleEntries[key]
	if !ok {
		return nil
	}
	tenant := e.ruleTenant[key]

	e.totalEntries -= entries
	if e.totalEntries < 0 {
		e.totalEntries = 0 // defensive: must never go negative
	}
	e.tenantRuleCount[tenant]--
	if e.tenantRuleCount[tenant] <= 0 {
		delete(e.tenantRuleCount, tenant)
	}
	delete(e.ruleEntries, key)
	delete(e.ruleTenant, key)
	return nil
}

// Stats returns a snapshot of current reservations, for
// TelemetryEmitter/diagnostics use.
func (e *NodeQuotaEnforcer) Stats() (totalEntries int, tenantRuleCounts map[string]int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make(map[string]int, len(e.tenantRuleCount))
	for k, v := range e.tenantRuleCount {
		out[k] = v
	}
	return e.totalEntries, out
}

var _ QuotaEnforcer = (*NodeQuotaEnforcer)(nil)
