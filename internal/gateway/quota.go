// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"sync"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
)

// Default limits for NodeQuotaEnforcer. Both are coarse, node-level admission
// caps, not bandwidth or per-flow rate limits.
const (
	// DefaultMaxRulesPerTenant bounds how many rules one tenant may have
	// registered on a gateway node at once. A rule may carry up to eight VIP
	// addresses, so this also bounds a tenant's worst-case map footprint to
	// eight times this value.
	DefaultMaxRulesPerTenant = 64

	// DefaultMaxRuleTableEntries is the node-wide ceiling across every tenant,
	// defaulting to the map's own capacity. Once desired state would fill the
	// map, writes start failing mid-reconcile with no clean way to roll back a
	// partial apply, so this must be enforced before any rule is applied.
	DefaultMaxRuleTableEntries = edgemap.MaxVIPTableEntries
)

// NodeQuotaEnforcer enforces two coarse, node-level admission caps entirely
// from control-plane state the engine already holds, with no map read:
//
//  1. No single tenant may register more than MaxRulesPerTenant rules on this
//     node at once.
//  2. The total map rows every tenant's rules would occupy, one per VIP
//     address, may not exceed MaxRuleTableEntries.
//
// It deliberately does no per-flow or per-tenant rate limiting. The map's key
// carries no tenant dimension, a VIP being globally unique, so attributing a
// flow back to a tenant would mean changing the packet-path key layout. A
// meaningful rate quota also needs a time-windowed rate rather than the
// cumulative, never-reset counters the map carries: a long-lived, popular rule
// eventually crosses any static cumulative threshold, which is success rather
// than misbehavior. Calibrating real thresholds needs live traffic data this
// repo does not have. This is the enforceable subset buildable without it.
type NodeQuotaEnforcer struct {
	mu sync.Mutex

	maxRulesPerTenant   int
	maxRuleTableEntries int

	// tenantRuleCount and totalEntries are the enforcer's own record of what it
	// has reserved, not read back from the map, so reserve and release stay
	// correct before a rule has been applied and has any row to read.
	tenantRuleCount map[string]int
	ruleTenant      map[string]string
	ruleEntries     map[string]int
	totalEntries    int
}

// NewNodeQuotaEnforcer returns a NodeQuotaEnforcer with the given limits. Use
// the package defaults in production.
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
// reserves its map footprint. Idempotent for a key already reserved:
// re-checking, or changing, an active rule's VIP count never double-counts it.
// That is required because the engine calls this for every desired rule on
// every pass, not only for new ones.
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
		// The tenant changed for an existing rule key. That should not
		// happen, no caller mutating a rule's tenant in place, but guard
		// against miscounting either bucket if it ever does.
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

// Release frees the reservation held for key, if any. A key that was never
// reserved is not an error.
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
