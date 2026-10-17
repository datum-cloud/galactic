// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import "github.com/prometheus/client_golang/prometheus"

const metricsNamespace = "galactic_ingress_sidecar"

// Metrics is this sidecar's Prometheus surface: active VRF and route counts,
// reconcile error rate and latency, and teardown queue depth. Build it once,
// register it once at startup, then pass it into the store.
type Metrics struct {
	VRFActive     prometheus.Gauge
	RouteActive   prometheus.Gauge
	VRFPending    prometheus.Gauge
	RoutePending  prometheus.Gauge
	ReconcileErrs *prometheus.CounterVec
	ReconcileTime prometheus.Histogram
	Reapplies     prometheus.Counter
}

// NewMetrics builds a fresh, unregistered Metrics. Call MustRegister once
// at process startup.
func NewMetrics() *Metrics {
	return &Metrics{
		VRFActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "vrf_active",
			Help: "Per-VPC VRF devices this sidecar tracks as installed, including those draining " +
				"through their teardown grace period. Store state, not a check of the kernel.",
		}),
		RouteActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_active",
			Help: "Installed route claims, one per EndpointSlice, including those draining. Claims sharing " +
				"a prefix share one kernel route, so this can exceed the routes installed.",
		}),
		VRFPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "vrf_teardown_pending",
			Help: "VRF devices past their last route as of the last sweep: those within their grace period " +
				"and those whose removal failed.",
		}),
		RoutePending: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_teardown_pending",
			Help: "Route claims whose EndpointSlice is gone as of the last sweep: those within their grace " +
				"period and those whose removal failed.",
		}),
		ReconcileErrs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reconcile_errors_total",
			Help: "Backend errors, by kind (ensure_vrf, ensure_route, remove_vrf, remove_route, " +
				"reapply_vrf, reapply_route, prune_datapath).",
		}, []string{"kind"}),
		ReconcileTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "reconcile_duration_seconds",
			Help: "Time each desired-state update took to apply, including waiting for the store's lock. " +
				"Does not cover sweeps.",
			Buckets: prometheus.DefBuckets,
		}),
		Reapplies: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reapply_total",
			Help: "Reapply passes over every tracked VRF and route: after the shared eBPF datapath was " +
				"reloaded, after this sidecar's rows went missing from it, and retries of a pass that failed.",
		}),
	}
}

// MustRegister registers every metric this type owns against reg, panicking on
// a duplicate. Callers do this once per process, at startup.
func (m *Metrics) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(m.VRFActive, m.RouteActive, m.VRFPending, m.RoutePending,
		m.ReconcileErrs, m.ReconcileTime, m.Reapplies)
}
