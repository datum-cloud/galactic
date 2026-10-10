// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// egressSubsystem names galactic-cni's egress control-loop series.
const egressSubsystem = "egress"

// EgressControl is galactic-cni's own view of the egress shard groups: which
// mode it was configured for, whether its EgressShard watch has ever listed
// the cluster, how many routes still name a group, and whether its sweeps are
// failing. These come from the control loop rather than from the maps, so a
// node that was told to run hashed mode but never got as far as publishing a
// group still says so: the absence of the map-derived series is not health.
//
// All methods are safe on a nil receiver, which tests use.
type EgressControl struct {
	mode        *prometheus.GaugeVec
	watchSynced prometheus.Gauge
	groupRoutes *prometheus.GaugeVec
	sweepErrors *prometheus.CounterVec
	lastSweep   prometheus.Gauge
}

// NewEgressControl builds the series and registers them with reg.
func NewEgressControl(reg prometheus.Registerer) *EgressControl {
	c := &EgressControl{
		mode: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: egressNamespace, Subsystem: egressSubsystem, Name: "mode",
			Help: "1 for the egress mode galactic-cni is configured with (GALACTIC_CNI_EGRESS_MODE), 0 for the other.",
		}, []string{"mode"}),
		watchSynced: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: egressNamespace, Subsystem: egressSubsystem, Name: "shard_watch_synced",
			Help: "1 once galactic-cni's EgressShard watch has listed the cluster, else 0. Hashed mode keeps the " +
				"shard groups it last published until then.",
		}),
		groupRoutes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: egressNamespace, Subsystem: egressSubsystem, Name: "group_routes",
			Help: "egress_route_table entries naming an egress shard group after the last successful sweep, by " +
				"translation class. Must be 0 before rolling back to a release that predates shard groups.",
		}, []string{labelClass}),
		sweepErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: egressNamespace, Subsystem: egressSubsystem, Name: "sweep_errors_total",
			Help: "Egress route sweep failures, by stage: apply (publishing a shard group), refresh (reading or " +
				"rewriting egress_route_table), watch (listing EgressShards), close and disable (retiring groups).",
		}, []string{"stage"}),
		lastSweep: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: egressNamespace, Subsystem: egressSubsystem, Name: "last_successful_sweep_timestamp_seconds",
			Help: "Unix time of the last egress route sweep that finished without an error.",
		}),
	}
	reg.MustRegister(c.mode, c.watchSynced, c.groupRoutes, c.sweepErrors, c.lastSweep)
	for _, stage := range []string{"apply", "refresh", "watch", "close", "disable"} {
		c.sweepErrors.WithLabelValues(stage)
	}
	return c
}

// SetMode records the configured mode.
func (c *EgressControl) SetMode(mode string, all ...string) {
	if c == nil {
		return
	}
	for _, m := range all {
		v := 0.0
		if m == mode {
			v = 1
		}
		c.mode.WithLabelValues(m).Set(v)
	}
}

// SetWatchSynced records whether the EgressShard watch has synced.
func (c *EgressControl) SetWatchSynced(synced bool) {
	if c == nil {
		return
	}
	v := 0.0
	if synced {
		v = 1
	}
	c.watchSynced.Set(v)
}

// SetGroupRoutes records the routes naming each class's group.
func (c *EgressControl) SetGroupRoutes(byClass map[string]int) {
	if c == nil {
		return
	}
	c.groupRoutes.Reset()
	for class, n := range byClass {
		c.groupRoutes.WithLabelValues(class).Set(float64(n))
	}
}

// SweepError counts a failure at stage.
func (c *EgressControl) SweepError(stage string) {
	if c == nil {
		return
	}
	c.sweepErrors.WithLabelValues(stage).Inc()
}

// SweepSucceeded records a sweep that finished without an error.
func (c *EgressControl) SweepSucceeded(at time.Time) {
	if c == nil {
		return
	}
	c.lastSweep.Set(float64(at.Unix()))
}
