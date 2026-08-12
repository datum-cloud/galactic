// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import "context"

// Datapath is the engine's interface onto the actual NAT/load-balancing
// dataplane for one DesiredRule. GoBGP, via galactic-router's existing
// embedding, owns all BGP speaking (the design plan's Active-Active BGP
// model); no BGP speaker lives in this interface's implementations at
// all.
//
// KernelDatapath (kerneldatapath.go) is the real implementation, backed by
// internal/plumbing/ebpf/edgemap's RuleTable API onto a loaded
// internal/plumbing/ebpf/edgeprog.EdgenatObjects. Unlike an earlier,
// rejected design's identically-named interface, there is no
// lpmOverrides parameter here at all: that existed solely to work around a
// LoxiLB-internal routing-engine self-collision bug, and this design has
// no internal routing engine of its own for a return packet to collide
// with (see doc.go). NoopDatapath remains available for tests and any
// caller not yet wired to a loaded, attached edgeprog program.
type Datapath interface {
	// ApplyRule programs (or reprograms) rule's ingress DNAT/LB state.
	ApplyRule(ctx context.Context, rule DesiredRule) error

	// RemoveRule tears down rule_table state for the rule identified by
	// key. The caller (the future NetworkRule controller) must withdraw
	// the rule's BGP route before calling this, never after — removing
	// NAT state first while the route is still advertised risks
	// blackholing in-flight flows through a translation that no longer
	// exists.
	RemoveRule(ctx context.Context, key string) error

	// Generation returns a snapshot of the datapath's own monotonic
	// clock, for crash-recovery purposes. Callers intending to call
	// ReconcileOrphans must capture this immediately *before* listing the
	// NetworkRule CRDs that become that call's live set — see
	// internal/plumbing/ebpf/edgemap's RuleTable.Generation doc comment
	// for why the ordering matters.
	Generation() uint64

	// ReconcileOrphans removes rule_table state whose owning rule is
	// absent from live and was written before cutoff — the datapath-level
	// half of Engine.ReconcileOrphans (recovery.go).
	ReconcileOrphans(ctx context.Context, live []DesiredRule, cutoff uint64) error
}

// QuotaEnforcer is the engine's interface onto per-tenant conntrack/NAT
// table quota enforcement, called once per rule per convergence pass so a
// misbehaving tenant's traffic can be capped before it exhausts shared
// conntrack/eBPF map capacity on its assigned gateway node.
//
// NodeQuotaEnforcer (quota.go) is the real (Phase E) implementation: a
// coarse, node-level admission cap (max rules per tenant, max total
// rule_table entries), not per-flow/conntrack rate limiting — see that
// type's doc comment for why the latter needs live traffic data to
// calibrate sensible thresholds against, which this repo does not have
// yet (the design plan's Phase D was authored as manifests only, not
// exercised against a live cluster). NoopQuotaEnforcer remains available
// for tests and always reports quota as available.
type QuotaEnforcer interface {
	// CheckAndReserve reports whether rule is within its per-tenant quota
	// and, if so, reserves the resources ApplyRule is about to consume.
	CheckAndReserve(ctx context.Context, rule DesiredRule) (bool, error)

	// Release frees any quota reservation held for key, called during
	// teardown, alongside Datapath.RemoveRule.
	Release(ctx context.Context, key string) error
}

// TelemetryEmitter is the engine's interface onto telemetry for
// conntrack/NAT entry counts, drop counters, and primary/secondary BGP
// advertisement state per VIP.
//
// PrometheusTelemetryEmitter (telemetry.go) is the real (Phase E)
// implementation, covering only what these call sites uniquely know
// (primary/secondary placement, control-plane-level rejections) --
// rule_table's own per-packet counters are exposed separately by
// internal/plumbing/ebpf/edgemetrics's pull-based Collector; see both
// types' doc comments for the full split. NoopTelemetryEmitter remains
// available for tests and drops every call on the floor.
type TelemetryEmitter interface {
	// RuleApplied is called after a successful Datapath.ApplyRule, so a
	// caller can emit primary/secondary advertisement state and NAT/
	// conntrack counters for the rule.
	RuleApplied(ctx context.Context, rule DesiredRule)

	// RuleRemoved is called after a successful teardown of key.
	RuleRemoved(ctx context.Context, key string)

	// DropObserved records a dropped packet/flow for key, distinguishing
	// quota-enforcement drops from genuine failures via reason.
	DropObserved(ctx context.Context, key string, reason string)
}

// NoopDatapath is a placeholder Datapath implementation for tests and any
// caller not yet wired to a loaded, attached edgeprog program —
// KernelDatapath (kerneldatapath.go) is the real implementation; see
// Datapath's doc comment.
type NoopDatapath struct{}

func (NoopDatapath) ApplyRule(context.Context, DesiredRule) error { return nil }
func (NoopDatapath) RemoveRule(context.Context, string) error     { return nil }
func (NoopDatapath) Generation() uint64                           { return 0 }
func (NoopDatapath) ReconcileOrphans(context.Context, []DesiredRule, uint64) error {
	return nil
}

// NoopQuotaEnforcer is the TODO-marked placeholder QuotaEnforcer
// implementation. It always reports quota as available — see
// QuotaEnforcer's doc comment for why real enforcement is deferred.
type NoopQuotaEnforcer struct{}

// CheckAndReserve always allows the rule.
func (NoopQuotaEnforcer) CheckAndReserve(context.Context, DesiredRule) (bool, error) {
	return true, nil
}

// Release is a no-op.
func (NoopQuotaEnforcer) Release(context.Context, string) error {
	return nil
}

// NoopTelemetryEmitter is the TODO-marked placeholder TelemetryEmitter
// implementation. It drops every call — see TelemetryEmitter's doc
// comment for why the real implementation is deferred.
type NoopTelemetryEmitter struct{}

// RuleApplied is a no-op.
func (NoopTelemetryEmitter) RuleApplied(context.Context, DesiredRule) {}

// RuleRemoved is a no-op.
func (NoopTelemetryEmitter) RuleRemoved(context.Context, string) {}

// DropObserved is a no-op.
func (NoopTelemetryEmitter) DropObserved(context.Context, string, string) {}
