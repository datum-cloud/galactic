// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
)

// Backend operations, as operations_total labels them.
const (
	OpEnsureVRF    = "ensure_vrf"
	OpEnsureRoute  = "ensure_route"
	OpRemoveVRF    = "remove_vrf"
	OpRemoveRoute  = "remove_route"
	OpReapplyVRF   = "reapply_vrf"
	OpReapplyRoute = "reapply_route"
)

// Operation results.
const (
	OpSuccess = "success"
	OpError   = "error"
)

// Teardown resources, as teardown_overdue labels them.
const (
	ResourceRoute = "route"
	ResourceVRF   = "vrf"
)

var (
	backendOperations = []string{OpEnsureVRF, OpEnsureRoute, OpRemoveVRF, OpRemoveRoute, OpReapplyVRF, OpReapplyRoute}
	opResults         = []string{OpSuccess, OpError}
	teardownResources = []string{ResourceRoute, ResourceVRF}
)

// ConvergenceMetrics reports how far this sidecar's host state is from what
// its EndpointSlices ask for: the claims it wants, those whose latest update
// is not applied yet and for how long, teardown that has run past its grace
// period, and every backend operation's outcome. The Store updates them at
// each change, under its own lock; a scrape only reads them. Every method is
// safe on a nil receiver.
type ConvergenceMetrics struct {
	desired      prometheus.Gauge
	applyPending prometheus.Gauge
	oldest       prometheus.Gauge
	overdue      *prometheus.GaugeVec
	operations   *prometheus.CounterVec
	applyDelay   prometheus.Histogram
}

// delayBuckets span a prompt apply or projection, well under a second, to one
// stuck for many minutes.
var delayBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600}

// NewConvergenceMetrics creates convergence metrics on the instrumentation
// library's registry, every series at zero. The registry keeps the series
// across calls, so each call sets them back to zero.
func NewConvergenceMetrics() *ConvergenceMetrics {
	m := &ConvergenceMetrics{
		desired: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_claims_desired",
			Help: "Route claims, one per selected and ready EndpointSlice, that this sidecar wants installed, " +
				"including any whose install failed.",
		}),
		applyPending: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_claims_apply_pending",
			Help: "Desired route claims whose latest update is not applied yet, whether or not an earlier " +
				"version of the route is installed.",
		}),
		oldest: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "route_apply_oldest_pending_timestamp_seconds",
			Help: "Unix time the longest-pending desired claim stopped being applied; 0 when none is pending. " +
				"Retries and newer updates of a pending claim do not reset it.",
		}),
		overdue: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "teardown_overdue",
			Help: "Routes or VRFs, by resource, whose own grace period has run out but whose removal has not " +
				"completed, as of the last sweep.",
		}, []string{"resource"}),
		operations: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "operations_total",
			Help: "Completed backend operations, by operation (ensure_vrf, ensure_route, remove_vrf, " +
				"remove_route, reapply_vrf, reapply_route) and result (success, error).",
		}, []string{"operation", resultLabel}),
		applyDelay: newHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "route_apply_delay_seconds",
			Help: "Time from a route claim becoming apply-pending, when its EndpointSlice is first observed " +
				"or updated, to that update being applied, including failed attempts and retries.",
			Buckets: delayBuckets,
		}),
	}
	for _, g := range []prometheus.Gauge{m.desired, m.applyPending, m.oldest} {
		g.Set(0)
	}
	m.overdue.Reset()
	m.operations.Reset()
	for _, r := range teardownResources {
		m.overdue.WithLabelValues(r)
	}
	for _, op := range backendOperations {
		for _, res := range opResults {
			m.operations.WithLabelValues(op, res)
		}
	}
	return m
}

// operation records one completed backend operation.
func (m *ConvergenceMetrics) operation(op string, err error) {
	if m == nil {
		return
	}
	result := OpSuccess
	if err != nil {
		result = OpError
	}
	m.operations.WithLabelValues(op, result).Inc()
}

// applied records that a claim's pending update applied after waiting d.
func (m *ConvergenceMetrics) applied(d time.Duration) {
	if m == nil {
		return
	}
	m.applyDelay.Observe(max(d, 0).Seconds())
}

// claims publishes the desired and apply-pending claim counts and the oldest
// pending claim's start, the zero Time when none is pending.
func (m *ConvergenceMetrics) claims(desired, pending int, oldest time.Time) {
	if m == nil {
		return
	}
	m.desired.Set(float64(desired))
	m.applyPending.Set(float64(pending))
	if pending == 0 || oldest.IsZero() {
		m.oldest.Set(0)
		return
	}
	m.oldest.Set(unixSecondsOf(oldest))
}

// overdueTeardown publishes a sweep's overdue routes and VRFs.
func (m *ConvergenceMetrics) overdueTeardown(routes, vrfs int) {
	if m == nil {
		return
	}
	m.overdue.WithLabelValues(ResourceRoute).Set(float64(routes))
	m.overdue.WithLabelValues(ResourceVRF).Set(float64(vrfs))
}

// unixSecondsOf is t as fractional Unix seconds, exact to the nanosecond.
func unixSecondsOf(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}
