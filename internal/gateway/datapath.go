// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import "context"

// Datapath is the engine's interface onto the Maglev load-balancing dataplane
// for one rule. No BGP speaker lives in any implementation of it; the router
// owns all BGP speaking. There is no primary or secondary node either: under
// the anycast model every gateway node advertises and serves every rule
// identically.
//
// KernelDatapath is the real implementation, backed by the map layer over a
// loaded edge program. NoopDatapath is available for tests and for a caller not
// yet wired to a loaded, attached program.
type Datapath interface {
	// ApplyRule programs (or reprograms) rule's ingress Maglev/DSR
	// load-balancing state.
	ApplyRule(ctx context.Context, rule DesiredRule) error

	// RemoveRule tears down vip_table state for the rule identified by key.
	// The caller must withdraw the rule's BGP route before calling this, never
	// after: removing load-balancing state while the route is still advertised
	// risks blackholing in-flight flows that would still resolve to a live
	// backend.
	RemoveRule(ctx context.Context, key string) error

	// Generation returns a snapshot of the datapath's monotonic clock, for
	// crash recovery. A caller intending to call ReconcileOrphans must read it
	// immediately before listing the CRDs that become that call's live set.
	Generation() uint64

	// ReconcileOrphans removes vip_table state whose owning rule is absent from
	// live and was written before cutoff.
	ReconcileOrphans(ctx context.Context, live []DesiredRule, cutoff uint64) error
}

// QuotaEnforcer is the engine's interface onto per-tenant vip_table quota,
// called once per rule per convergence pass, so a misbehaving tenant's rules
// are capped before they exhaust the shared map's capacity on its gateway node.
//
// NodeQuotaEnforcer is the real implementation: a coarse node-level admission
// cap on rules per tenant and total entries, not per-flow rate limiting, which
// would need live traffic data to calibrate against. NoopQuotaEnforcer always
// reports quota as available.
type QuotaEnforcer interface {
	// CheckAndReserve reports whether rule is within its per-tenant quota
	// and, if so, reserves the resources ApplyRule is about to consume.
	CheckAndReserve(ctx context.Context, rule DesiredRule) (bool, error)

	// Release frees any quota reservation held for key, called during
	// teardown, alongside Datapath.RemoveRule.
	Release(ctx context.Context, key string) error
}

// TelemetryEmitter is the engine's interface onto telemetry for events only
// knowable at the engine's own call sites, currently rule applications rejected
// before reaching the datapath.
//
// PrometheusTelemetryEmitter is the real implementation. The datapath's
// per-packet counters are exposed separately by a pull-based collector.
// NoopTelemetryEmitter drops every call.
type TelemetryEmitter interface {
	// RuleApplied is called after a rule is successfully applied, so a caller
	// can emit advertisement state and counters for it.
	RuleApplied(ctx context.Context, rule DesiredRule)

	// RuleRemoved is called after a successful teardown of key.
	RuleRemoved(ctx context.Context, key string)

	// DropObserved records a dropped packet/flow for key, distinguishing
	// quota-enforcement drops from genuine failures via reason.
	DropObserved(ctx context.Context, key string, reason string)
}

// NoopDatapath is a placeholder for tests and for a caller not yet wired to a
// loaded, attached program.
type NoopDatapath struct{}

func (NoopDatapath) ApplyRule(context.Context, DesiredRule) error { return nil }
func (NoopDatapath) RemoveRule(context.Context, string) error     { return nil }
func (NoopDatapath) Generation() uint64                           { return 0 }
func (NoopDatapath) ReconcileOrphans(context.Context, []DesiredRule, uint64) error {
	return nil
}

// NoopQuotaEnforcer always reports quota as available.
type NoopQuotaEnforcer struct{}

// CheckAndReserve always allows the rule.
func (NoopQuotaEnforcer) CheckAndReserve(context.Context, DesiredRule) (bool, error) {
	return true, nil
}

// Release is a no-op.
func (NoopQuotaEnforcer) Release(context.Context, string) error {
	return nil
}

// NoopTelemetryEmitter drops every call.
type NoopTelemetryEmitter struct{}

// RuleApplied is a no-op.
func (NoopTelemetryEmitter) RuleApplied(context.Context, DesiredRule) {}

// RuleRemoved is a no-op.
func (NoopTelemetryEmitter) RuleRemoved(context.Context, string) {}

// DropObserved is a no-op.
func (NoopTelemetryEmitter) DropObserved(context.Context, string, string) {}
