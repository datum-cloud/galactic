// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"
)

const metricsNamespace = "galactic_service_route"

// Labels and values of the reconciliations metric.
const (
	reconcileResultLabel   = "result"
	ReconcileResultSuccess = "success"
	ReconcileResultError   = "error"
	ReconcileReasonNone    = "none"
)

// Reasons a ServiceRoutePolicy reconcile fails, for the reason label of the
// reconciliations metric. Keep this set fixed and the routing observability
// doc in step with it.
const (
	ReconcileGetPolicy             = "get_policy"
	ReconcileRemoveDeleted         = "remove_deleted"
	ReconcileGetEndpoint           = "get_endpoint"
	ReconcileRevokeMissingEndpoint = "revoke_missing_endpoint"
	ReconcileProducerReports       = "producer_reports"
	ReconcileListAttachments       = "list_attachments"
	ReconcileConflictLookup        = "conflict_lookup"
	ReconcileDependencyNotReady    = "dependency_not_ready"
	ReconcileCompile               = "compile"
	ReconcileRefreshMaps           = "refresh_maps"
	ReconcileProgram               = "program"
	ReconcileAcceptStatus          = "accept_status"
	// ReconcileOther is any other failed reconcile, such as a status update
	// that failed while revoking a policy that is disabled, invalid or in
	// conflict.
	ReconcileOther = "other"
)

// ReconcileReasons lists every reason ObserveReconcile records.
var ReconcileReasons = []string{
	ReconcileReasonNone, ReconcileGetPolicy, ReconcileRemoveDeleted, ReconcileGetEndpoint,
	ReconcileRevokeMissingEndpoint, ReconcileProducerReports, ReconcileListAttachments, ReconcileConflictLookup,
	ReconcileDependencyNotReady, ReconcileCompile, ReconcileRefreshMaps, ReconcileProgram, ReconcileAcceptStatus,
	ReconcileOther,
}

// Metrics contains bounded-cardinality metrics for the node-local service
// route controller. Resource names are deliberately kept in logs instead of
// labels so a large tenant population does not create an unbounded registry.
type Metrics struct {
	reconciliations *prometheus.CounterVec
	reconcileTime   prometheus.Histogram
	operations      *prometheus.CounterVec
	programmed      prometheus.Gauge
	unresolved      prometheus.Gauge
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
			Help: "ServiceRoutePolicy reconciliations by outcome. A failed reconcile " +
				"carries the step that failed in reason; a successful one has reason none.",
		}, []string{reconcileResultLabel, labels.Reason}),
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
		unresolved: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "unresolved_next_hops",
			Help: "Tracked service paths with no next hop for their consumer attachment, " +
				"which forward to the destination address instead.",
		}),
		producers: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "producers",
			Help: "Producers of Spread ServiceEndpoints on this node, by health state. " +
				"Each endpoint's status.producers names them.",
		}, []string{"state"}),
	}
}

// ObserveReconcile records one reconcile. errorReason is one of the
// Reconcile reasons above, or empty on success. Any other value is recorded
// as ReconcileOther, so the label stays bounded.
func (m *Metrics) ObserveReconcile(errorReason string, duration time.Duration) {
	if m == nil {
		return
	}
	result, reason := ReconcileResultSuccess, ReconcileReasonNone
	if errorReason != "" {
		result, reason = ReconcileResultError, ReconcileOther
		if errorReason != ReconcileReasonNone && slices.Contains(ReconcileReasons, errorReason) {
			reason = errorReason
		}
	}
	m.reconciliations.WithLabelValues(result, reason).Inc()
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

// SetUnresolvedNextHops records how many tracked paths have no consumer next
// hop.
func (m *Metrics) SetUnresolvedNextHops(count int) {
	if m != nil {
		m.unresolved.Set(float64(count))
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
