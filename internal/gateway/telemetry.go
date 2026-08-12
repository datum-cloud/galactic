// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

const telemetryNamespace = "galactic_edge"

// labelRule is the Prometheus label name for a DesiredRule.Key value,
// shared across every metric below that carries one.
const labelRule = "rule"

// PrometheusTelemetryEmitter is a real (not stubbed) TelemetryEmitter,
// covering exactly the two things only knowable at Engine's own call
// sites -- not re-derivable from a live scrape of rule_table/conn_table
// state, which internal/plumbing/ebpf/edgemetrics's Collector already
// exposes separately (packets/bytes/dropped_packets/last_seen_ns per
// rule, same pull-at-scrape-time pattern as
// internal/plumbing/ebpf/metrics's Collector for the SRv6 uSID datapath):
//
//  1. Which gateway node is currently primary vs. secondary for a rule's
//     VIPs (DesiredRule.IsPrimary) -- an Active-Active BGP placement
//     decision this engine's own control plane made, not something the
//     datapath's own counters carry.
//  2. Rule applications rejected before ever reaching the datapath (e.g.
//     QuotaEnforcer denials) -- these never touch rule_table at all, so
//     rule_table's own DroppedPackets counter (a strictly datapath-level,
//     per-packet count) cannot see them.
type PrometheusTelemetryEmitter struct {
	rulePrimary       *prometheus.GaugeVec
	controlPlaneDrops *prometheus.CounterVec
}

// NewPrometheusTelemetryEmitter builds a fresh, unregistered
// PrometheusTelemetryEmitter. Call MustRegister once at process startup.
func NewPrometheusTelemetryEmitter() *PrometheusTelemetryEmitter {
	return &PrometheusTelemetryEmitter{
		rulePrimary: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: telemetryNamespace,
			Subsystem: labelRule,
			Name:      "is_primary",
			Help: "1 if this gateway node is the active-active primary (higher BGP local-pref) for " +
				"this rule's VIPs, 0 if secondary. Absent entirely once the rule is removed.",
		}, []string{labelRule}),
		controlPlaneDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: telemetryNamespace,
			Name:      "control_plane_drops_total",
			Help: "Rule applications rejected before ever reaching the datapath (e.g. quota_exceeded), " +
				"by rule and reason. Datapath-level packet drops (a rule that WAS applied, then dropped " +
				"traffic) are exposed separately by internal/plumbing/ebpf/edgemetrics's Collector.",
		}, []string{labelRule, "reason"}),
	}
}

// MustRegister registers every metric this type owns against reg. Panics
// on a duplicate registration, matching prometheus.Registerer.MustRegister's
// own documented behavior -- callers only ever do this once per process,
// at startup, same convention as internal/plumbing/ebpf/metrics's
// EventCounters.MustRegister.
func (e *PrometheusTelemetryEmitter) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(e.rulePrimary, e.controlPlaneDrops)
}

// RuleApplied records rule's current primary/secondary placement.
func (e *PrometheusTelemetryEmitter) RuleApplied(_ context.Context, rule DesiredRule) {
	v := 0.0
	if rule.IsPrimary {
		v = 1
	}
	e.rulePrimary.WithLabelValues(rule.Key).Set(v)
}

// RuleRemoved deletes key's is_primary series -- a removed rule has no
// primary/secondary state to report, and leaving a stale series behind
// would misreport it as still (say) secondary forever.
func (e *PrometheusTelemetryEmitter) RuleRemoved(_ context.Context, key string) {
	e.rulePrimary.DeleteLabelValues(key)
}

// DropObserved records a control-plane-level rejection for key, labeled by
// reason (e.g. "quota_exceeded" -- see Engine.applyRuleLocked).
func (e *PrometheusTelemetryEmitter) DropObserved(_ context.Context, key, reason string) {
	e.controlPlaneDrops.WithLabelValues(key, reason).Inc()
}

var _ TelemetryEmitter = (*PrometheusTelemetryEmitter)(nil)
