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
}

// NewMetrics builds a fresh, unregistered Metrics. Call MustRegister once
// at process startup.
func NewMetrics() *Metrics {
	return &Metrics{
		VRFActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "vrf_active",
			Help:      "Number of per-VPC VRF devices this sidecar currently has installed.",
		}),
		RouteActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_active",
			Help:      "Number of per-pod seg6 egress routes this sidecar currently has installed.",
		}),
		VRFPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "vrf_teardown_pending",
			Help:      "Number of VRF devices past their last live pod, waiting out their teardown grace period.",
		}),
		RoutePending: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_teardown_pending",
			Help:      "Number of routes whose EndpointSlice disappeared, waiting out their teardown grace period.",
		}),
		ReconcileErrs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reconcile_errors_total",
			Help:      "Reconcile errors, by kind (ensure_vrf, ensure_route, remove_vrf, remove_route).",
		}, []string{"kind"}),
		ReconcileTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "reconcile_duration_seconds",
			Help:      "Time taken by each Store.SetDesired call.",
			Buckets:   prometheus.DefBuckets,
		}),
	}
}

// MustRegister registers every metric this type owns against reg, panicking on
// a duplicate. Callers do this once per process, at startup.
func (m *Metrics) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(m.VRFActive, m.RouteActive, m.VRFPending, m.RoutePending, m.ReconcileErrs, m.ReconcileTime)
}
