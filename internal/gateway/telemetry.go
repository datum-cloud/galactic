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

// PrometheusTelemetryEmitter covers the one thing only knowable at the engine's
// own call sites: rule applications rejected before reaching the datapath, such
// as a quota denial. Those never touch the map at all, so its own drop counter,
// a strictly per-packet datapath count, cannot see them.
//
// Everything re-derivable from live map state is exposed separately by the
// metrics collector at scrape time instead. There is no per-rule placement
// gauge, every gateway node serving every rule identically under anycast.
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

// MustRegister registers every metric this type owns against reg, panicking on
// a duplicate as the underlying registry does. Callers do this once per process,
// at startup.
func (e *PrometheusTelemetryEmitter) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(e.controlPlaneDrops)
}

// RuleApplied is a no-op: there is no per-rule placement fact left to record.
// It is kept to satisfy the interface, and as the natural place for any future
// call-site-only fact this engine learns.
func (e *PrometheusTelemetryEmitter) RuleApplied(context.Context, DesiredRule) {}

// RuleRemoved is a no-op, for the same reason as RuleApplied.
func (e *PrometheusTelemetryEmitter) RuleRemoved(context.Context, string) {}

// DropObserved records a control-plane-level rejection for key, labeled by
// reason (e.g. "quota_exceeded" -- see Engine.applyRuleLocked).
func (e *PrometheusTelemetryEmitter) DropObserved(_ context.Context, key, reason string) {
	e.controlPlaneDrops.WithLabelValues(key, reason).Inc()
}

var _ TelemetryEmitter = (*PrometheusTelemetryEmitter)(nil)
