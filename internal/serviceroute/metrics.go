// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "galactic_service_route"

// Metrics contains bounded-cardinality metrics for the node-local service
// route controller. Resource names are deliberately kept in logs instead of
// labels so a large tenant population does not create an unbounded registry.
type Metrics struct {
	reconciliations *prometheus.CounterVec
	reconcileTime   prometheus.Histogram
	operations      *prometheus.CounterVec
	programmed      prometheus.Gauge
}

// NewMetrics creates the service-route metrics. Call MustRegister once during
// process startup.
func NewMetrics() *Metrics {
	reconcileTime := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "reconcile_duration_seconds",
		Help:      "Time spent reconciling a ServiceRoutePolicy.",
		Buckets:   prometheus.DefBuckets,
	})
	return &Metrics{
		reconciliations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reconciliations_total",
			Help:      "ServiceRoutePolicy reconciliations by outcome.",
		}, []string{"result"}),
		reconcileTime: reconcileTime,
		operations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "route_operations_total",
			Help:      "Service route dataplane operations by operation and outcome.",
		}, []string{"operation", "result"}),
		programmed: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "programmed_routes",
			Help:      "Number of local route intents currently tracked by the controller.",
		}),
	}
}

// MustRegister registers all metrics owned by this package.
func (m *Metrics) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(m.reconciliations, m.reconcileTime, m.operations, m.programmed)
}

func (m *Metrics) ObserveReconcile(result string, duration time.Duration) {
	if m == nil {
		return
	}
	m.reconciliations.WithLabelValues(result).Inc()
	m.reconcileTime.Observe(duration.Seconds())
}

func (m *Metrics) ObserveOperation(operation string, err error) {
	if m == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	m.operations.WithLabelValues(operation, result).Inc()
}

func (m *Metrics) SetProgrammedRoutes(count int) {
	if m != nil {
		m.programmed.Set(float64(count))
	}
}
