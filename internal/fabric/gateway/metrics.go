// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"github.com/prometheus/client_golang/prometheus"
)

// labelOutcome is the metric label carrying an operation's outcome.
const labelOutcome = "outcome"

// Metrics is the gateway's instrumentation, registered with the
// controller-runtime registry so it is served with the manager's metrics.
// Request IDs and targets are never labels.
type Metrics struct {
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
		m.truncated, m.stageLatency, m.inFlight, m.staleObjects, m.certExpiry, m.credentialsOK)
	return m
}

// QueueWait records a granted wait.
func (m *Metrics) QueueWait(seconds float64) { m.queueWait.Observe(seconds) }

// CertificateExpiry records the loaded certificate's expiry.
func (m *Metrics) CertificateExpiry(unix float64) { m.certExpiry.Set(unix) }

// CredentialsLoaded records whether credentials are loaded.
func (m *Metrics) CredentialsLoaded(ok bool) {
	if ok {
		m.credentialsOK.Set(1)
	} else {
		m.credentialsOK.Set(0)
	}
}
