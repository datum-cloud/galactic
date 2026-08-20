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
// covering the one thing only knowable at Engine's own call sites -- not
// re-derivable from a live scrape of vip_table state, which
// internal/plumbing/ebpf/edgemetrics's Collector already exposes separately
// (packets/bytes/dropped_packets/last_seen_ns per rule, same
// pull-at-scrape-time pattern as internal/plumbing/ebpf/metrics's Collector
// for the SRv6 uSID datapath): rule applications rejected before ever
// reaching the datapath (e.g. QuotaEnforcer denials). These never touch
// vip_table at all, so vip_table's own DroppedPackets counter (a strictly
// datapath-level, per-packet count) cannot see them.
//
// Unlike this engine's Full-NAT predecessor, there is no primary/secondary
// placement gauge here: DSR's anycast model means every gateway node
// serves every rule identically, so there is no per-rule placement state
// left to report (see doc.go).
type PrometheusTelemetryEmitter struct {
	controlPlaneDrops *prometheus.CounterVec
}

// NewPrometheusTelemetryEmitter builds a fresh, unregistered
// PrometheusTelemetryEmitter. Call MustRegister once at process startup.
func NewPrometheusTelemetryEmitter() *PrometheusTelemetryEmitter {
	return &PrometheusTelemetryEmitter{
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
	reg.MustRegister(e.controlPlaneDrops)
}

// RuleApplied is a no-op: unlike this engine's Full-NAT predecessor, there
// is no per-rule primary/secondary placement fact left to record here (see
// this type's doc comment). Kept as a method (rather than removed) to
// satisfy the TelemetryEmitter interface, and as the natural place for any
// future call-site-only fact this engine learns.
func (e *PrometheusTelemetryEmitter) RuleApplied(context.Context, DesiredRule) {}

// RuleRemoved is a no-op, for the same reason as RuleApplied.
func (e *PrometheusTelemetryEmitter) RuleRemoved(context.Context, string) {}

// DropObserved records a control-plane-level rejection for key, labeled by
// reason (e.g. "quota_exceeded" -- see Engine.applyRuleLocked).
func (e *PrometheusTelemetryEmitter) DropObserved(_ context.Context, key, reason string) {
	e.controlPlaneDrops.WithLabelValues(key, reason).Inc()
}

var _ TelemetryEmitter = (*PrometheusTelemetryEmitter)(nil)
