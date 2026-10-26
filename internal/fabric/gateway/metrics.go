// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
)

// labelOutcome is the metric label carrying an operation's outcome,
// labelOperation the one carrying a Looking Glass request's operation, and
// labelReason the one carrying why something ended or was refused.
const (
	labelOutcome   = "outcome"
	labelOperation = "operation"
	labelReason    = "reason"
)

// Metrics is the gateway's instrumentation, registered with the
// controller-runtime registry so it is served with the manager's metrics.
// Every label takes values from a fixed set: request IDs, project IDs,
// service and operator names, nodes and targets are never labels. A nil
// *Metrics records nothing.
type Metrics struct {
	reg prometheus.Registerer

	serviceRequests   *prometheus.CounterVec
	serviceOutcomes   *prometheus.CounterVec
	serviceDuration   *prometheus.HistogramVec
	admissionRefusals *prometheus.CounterVec
	packetsCharged    *prometheus.CounterVec

	queries       *prometheus.CounterVec
	nodes         *prometheus.CounterVec
	rpcDuration   *prometheus.HistogramVec
	queueDepth    prometheus.GaugeFunc
	queueWait     prometheus.Histogram
	statusWrites  *prometheus.CounterVec
	statusBytes   prometheus.Histogram
	truncated     prometheus.Counter
	stageLatency  *prometheus.HistogramVec
	inFlight      prometheus.Gauge
	staleObjects  prometheus.Gauge
	certExpiry    prometheus.Gauge
	credentialsOK prometheus.Gauge
}

// NewMetrics builds the gateway metrics; depth reports the executor's queue.
func NewMetrics(reg prometheus.Registerer, depth func() float64) *Metrics {
	m := &Metrics{
		reg: reg,
		serviceRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_gateway_service_requests_total",
			Help: "Looking Glass service requests that ended on this replica, by operation and reason: the " +
				"terminal coverage reason of a delivered stream, the refusal's reason before its snapshot, or " +
				"DeliveryFailed when its stream broke.",
		}, []string{labelOperation, labelReason}),
		serviceOutcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_gateway_service_router_outcomes_total",
			Help: "Routers of Looking Glass service requests, by operation and outcome: OK, a failure reason, or " +
				"the reason a router was omitted from the request.",
		}, []string{labelOperation, labelOutcome}),
		serviceDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "fabric_api_gateway_service_request_duration_seconds",
			Help: "Time from the leader's receipt of a Looking Glass service request to the end of its stream, " +
				"for requests whose snapshot was delivered.",
			Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120},
		}, []string{labelOperation}),
		admissionRefusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_gateway_admission_refusals_total",
			Help: "Work the cell's aggregate admission refused, by traffic class (service, operator, fabricquery), " +
				"limiter scope (cell, project, destination, queue) and reason (Throttled, QueueFull, " +
				"LimiterUnavailable).",
		}, []string{"class", "scope", labelReason}),
		packetsCharged: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_gateway_probe_packets_charged_total",
			Help: "Worst-case probe packets charged to the cell's budgets, by traffic class.",
		}, []string{"class"}),
		queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_gateway_queries_total",
			Help: "FabricQuery executions finished, by query type and terminal reason.",
		}, []string{"type", "reason"}),
		nodes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_gateway_node_outcomes_total",
			Help: "Per-node outcomes of executions: OK, an error code, or an omission reason.",
		}, []string{labelOutcome}),
		rpcDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "fabric_api_gateway_node_rpc_duration_seconds",
			Help:    "Execute RPC duration to a node, by query type and outcome code.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"type", "code"}),
		queueDepth: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_gateway_queue_depth",
			Help: "Node RPCs waiting for a cell execution slot.",
		}, depth),
		queueWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "fabric_api_gateway_queue_wait_seconds",
			Help:    "Time node RPCs waited for a cell execution slot.",
			Buckets: []float64{.001, .01, .1, .5, 1, 5, 10, 30},
		}),
		statusWrites: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_gateway_status_writes_total",
			Help: "FabricQuery status writes by kind (start, terminal) and outcome (ok, conflict, error).",
		}, []string{"kind", labelOutcome}),
		statusBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "fabric_api_gateway_status_bytes",
			Help:    "Serialized size of terminal FabricQuery objects.",
			Buckets: prometheus.ExponentialBuckets(1024, 2, 10),
		}),
		truncated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fabric_api_gateway_truncated_results_total",
			Help: "Terminal results shaped down to the object byte budget.",
		}),
		stageLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "fabric_api_gateway_stage_latency_seconds",
			Help: "Latency of each stage of a query's life as seen by the cell: receipt (creation to first " +
				"reconcile), execution (start marker to last node answer), completion (creation to terminal status).",
			Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120},
		}, []string{"stage"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_gateway_executions_in_flight",
			Help: "FabricQuery executions running on this gateway.",
		}),
		staleObjects: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_gateway_stale_objects",
			Help: "FabricQuery objects in this cell past their expiration (or completion) plus retention and " +
				"cleanup grace, which neither the federation nor the janitor has deleted.",
		}),
		certExpiry: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_certificate_expiry_timestamp_seconds",
			Help: "NotAfter of the loaded client certificate.",
		}),
		credentialsOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_credentials_loaded",
			Help: "1 when valid mTLS credentials are loaded.",
		}),
	}
	reg.MustRegister(m.queries, m.nodes, m.rpcDuration, m.queueDepth, m.queueWait, m.statusWrites, m.statusBytes,
		m.truncated, m.stageLatency, m.inFlight, m.staleObjects, m.certExpiry, m.credentialsOK, m.serviceRequests,
		m.serviceOutcomes, m.serviceDuration, m.admissionRefusals, m.packetsCharged)
	return m
}

// RegisterService exports the Looking Glass switch's state as
// fabric_api_gateway_service_enabled.
func (m *Metrics) RegisterService(sw *ServiceSwitch) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "fabric_api_gateway_service_enabled",
		Help: "1 while this replica's service switch lets the Looking Glass service execute.",
	}, func() float64 {
		on, _ := sw.State()
		return boolGauge(on)
	}))
}

// RegisterAdmission exports the leader's aggregate admission state: its
// limiter state (one series per state, 1 for the current one), live service
// streams, limiter keys by kind, and clock's health.
func (m *Metrics) RegisterAdmission(a *Admission, clock func() error) {
	for _, state := range []string{limit.StateReady, limit.StateRecovering, limit.StateUnavailable} {
		m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_gateway_limiter_state",
			Help: "1 for the aggregate limiter's current state: ready, recovering (in its recovery hold) or " +
				"unavailable (not the leader, or unable to confirm the election or the clock).",
			ConstLabels: prometheus.Labels{"state": state},
		}, func() float64 { return boolGauge(a.Authority.State() == state) }))
	}
	keys := func(kind string, n func() int) prometheus.Collector {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_gateway_limiter_keys",
			Help: "Keys the aggregate limiter holds, by kind: project (project and principal buckets), " +
				"destination (host and prefix buckets) and attempt (live attempt keys).",
			ConstLabels: prometheus.Labels{"kind": kind},
		}, func() float64 { return float64(n()) })
	}
	m.reg.MustRegister(
		keys("project", func() int { p, _ := a.Buckets.Keys(); return p }),
		keys("destination", func() int { _, d := a.Buckets.Keys(); return d }),
		keys("attempt", a.Attempts.Len),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_gateway_service_streams",
			Help: "Live Looking Glass service streams the leader holds, queued and draining ones included.",
		}, func() float64 { return float64(a.liveStreams()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_gateway_clock_synchronized",
			Help: "1 while the kernel reports its clock synchronised within the limiter's bound; the limiter " +
				"admits nothing otherwise.",
		}, func() float64 { return boolGauge(clock() == nil) }),
	)
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// trafficClass is the traffic class of a budget principal.
func trafficClass(principal string) string {
	switch {
	case strings.HasPrefix(principal, "operator/"):
		return "operator"
	case strings.HasPrefix(principal, "fabricquery/"):
		return "fabricquery"
	}
	return "service"
}

// refused counts an admission refusal of principal's work. Only the
// limiter's own refusals count: Throttled, QueueFull and
// LimiterUnavailable.
func (m *Metrics) refused(principal string, err error) {
	if m == nil {
		return
	}
	switch code := errcode.Of(err); code {
	case errcode.Throttled, errcode.QueueFull, errcode.LimiterUnavailable:
		scope := errcode.Metadata(err)[errcode.MetadataScope]
		if scope == "" {
			scope = string(limit.ScopeCell)
		}
		m.admissionRefusals.WithLabelValues(trafficClass(principal), scope, string(code)).Inc()
	}
}

// charged counts packets charged to principal.
func (m *Metrics) charged(principal string, packets int) {
	if m != nil {
		m.packetsCharged.WithLabelValues(trafficClass(principal)).Add(float64(packets))
	}
}

// QueueWait records a granted wait.
func (m *Metrics) QueueWait(seconds float64) { m.queueWait.Observe(seconds) }

// CertificateExpiry records the loaded certificate's expiry.
func (m *Metrics) CertificateExpiry(unix float64) { m.certExpiry.Set(unix) }

// CredentialsLoaded records whether credentials are loaded.
func (m *Metrics) CredentialsLoaded(ok bool) { m.credentialsOK.Set(boolGauge(ok)) }

// serviceRequest counts a service request that ended with reason.
func (m *Metrics) serviceRequest(req *servicev1.RunDiagnosticRequest, reason errcode.Code) {
	if m != nil {
		m.serviceRequests.WithLabelValues(serviceOperation(req), string(reason)).Inc()
	}
}

// serviceOutcome counts a selected router of a service request: OK, or its
// failure's reason.
func (m *Metrics) serviceOutcome(op string, err error) {
	if m == nil {
		return
	}
	outcome := "OK"
	if err != nil {
		outcome = string(errcode.Of(err))
	}
	m.serviceOutcomes.WithLabelValues(op, outcome).Inc()
}

// serviceOmitted counts each router a service request omitted, by its
// reason.
func (m *Metrics) serviceOmitted(op string, routers []Node) {
	if m == nil {
		return
	}
	for _, r := range routers {
		if !r.Selected {
			m.serviceOutcomes.WithLabelValues(op, r.OmittedReason).Inc()
		}
	}
}
