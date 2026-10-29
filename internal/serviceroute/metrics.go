// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
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
	producers       *prometheus.GaugeVec
}

// NewMetrics creates the service-route metrics on the instrumentation
// library's registry.
func NewMetrics() *Metrics {
	reconcileTime := metrics.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "reconcile_duration_seconds",
		Help:      "Time spent reconciling a ServiceRoutePolicy.",
		Buckets:   prometheus.DefBuckets,
	})
	return &Metrics{
		reconciliations: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reconciliations_total",
			Help:      "ServiceRoutePolicy reconciliations by outcome.",
		}, []string{"result"}),
		reconcileTime: reconcileTime,
		operations: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "route_operations_total",
			Help:      "Service route dataplane operations by operation and outcome.",
		}, []string{"operation", "result"}),
		programmed: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "programmed_routes",
			Help:      "Number of attachment-scoped eBPF service paths currently tracked by the controller.",
		}),
		producers: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "producers",
			Help: "Producers of Spread ServiceEndpoints on this node, by health state. " +
				"Each endpoint's status.producers names them.",
		}, []string{"state"}),
	}
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

// SetProducers records how many producers this node probes in each health
// state. A state missing from counts is set to zero.
func (m *Metrics) SetProducers(counts map[string]int) {
	if m == nil {
		return
	}
	for _, state := range []string{"Healthy", "Unhealthy", "Unknown"} {
		m.producers.WithLabelValues(state).Set(float64(counts[state]))
	}
}
