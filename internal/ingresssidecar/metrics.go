// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
)

const metricsNamespace = "galactic_ingress_sidecar"

// Metrics is this sidecar's Prometheus surface: active VRF and route counts,
// reconcile error rate and latency, and teardown queue depth. Build it once at
// startup, then pass it into the store.
type Metrics struct {
	VRFActive     prometheus.Gauge
	RouteActive   prometheus.Gauge
	VRFPending    prometheus.Gauge
	RoutePending  prometheus.Gauge
	ReconcileErrs *prometheus.CounterVec
	ReconcileTime prometheus.Histogram
	Reapplies     prometheus.Counter
}

// NewMetrics creates Metrics on the instrumentation library's registry.
// The registry keeps the series across calls, so each call starts them over.
func NewMetrics() *Metrics {
	m := &Metrics{
		VRFActive: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "vrf_active",
			Help: "Per-VPC VRF devices this sidecar tracks as installed, including those draining " +
				"through their teardown grace period. Store state, not a check of the kernel.",
		}),
		RouteActive: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_active",
			Help: "Installed route claims, one per EndpointSlice, including those draining. Claims sharing " +
				"a prefix share one kernel route, so this can exceed the routes installed.",
		}),
		VRFPending: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "vrf_teardown_pending",
			Help: "VRF devices past their last route as of the last sweep: those within their grace period " +
				"and those whose removal failed.",
		}),
		RoutePending: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_teardown_pending",
			Help: "Route claims whose EndpointSlice is gone as of the last sweep: those within their grace " +
				"period and those whose removal failed.",
		}),
		ReconcileErrs: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reconcile_errors_total",
			Help: "Backend errors, by kind (ensure_vrf, ensure_route, remove_vrf, remove_route, " +
				"reapply_vrf, reapply_route, prune_datapath).",
		}, []string{"kind"}),
		ReconcileTime: newHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "reconcile_duration_seconds",
			Help: "Time each desired-state update took to apply, including waiting for the store's lock. " +
				"Does not cover sweeps.",
			Buckets: prometheus.DefBuckets,
		}),
		Reapplies: newCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reapply_total",
			Help: "Reapply passes over every tracked VRF and route: after the shared eBPF datapath was " +
				"reloaded, after this sidecar's rows went missing from it, and retries of a pass that failed.",
		}),
	}
	for _, g := range []prometheus.Gauge{m.VRFActive, m.RouteActive, m.VRFPending, m.RoutePending} {
		g.Set(0)
	}
	m.ReconcileErrs.Reset()
	return m
}

// newCounter creates a counter with no labels on the instrumentation
// library's registry, at zero even when an earlier call created it. The
// registry holds it as a vector, so each call can replace its one series.
func newCounter(opts prometheus.CounterOpts) prometheus.Counter {
	v := metrics.NewCounterVec(opts, nil)
	v.Reset()
	return v.WithLabelValues()
}

// newHistogram is newCounter for a histogram.
func newHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	v := metrics.NewHistogramVec(opts, nil)
	v.Reset()
	return v.WithLabelValues().(prometheus.Histogram)
}
