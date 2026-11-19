// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"
	"google.golang.org/grpc/status"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

// Label names of the Worker claim metrics.
const (
	capabilityLabel = "capability"
	stateLabel      = "state"
	modeLabel       = "mode"
	operationLabel  = "operation"
)

// ClaimMetrics report the sidecar's Worker session, the capabilities Worker
// offers it, and the state of its claims.
type ClaimMetrics struct {
	connected    prometheus.Gauge
	capabilities *prometheus.GaugeVec
	claims       *prometheus.GaugeVec
	destinations *prometheus.GaugeVec
	operations   *prometheus.CounterVec
}

// NewClaimMetrics creates the Worker claim metrics on the instrumentation
// library's registry.
func NewClaimMetrics() *ClaimMetrics {
	connected := metrics.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "worker_connected",
		Help:      "1 while the sidecar holds a session with Galactic Worker on its node, else 0.",
	}, nil)
	connected.Reset()
	m := &ClaimMetrics{
		connected: connected.WithLabelValues(),
		capabilities: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "worker_capability",
			Help: "1 for each capability Worker reported at the start of the session, by state (available or " +
				"unavailable) and the reason it gave, such as ModuleNotRunning. The sidecar needs local.socket " +
				"and, for backends on other nodes, fabric.srv6.",
		}, []string{capabilityLabel, stateLabel, labels.Reason}),
		claims: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "worker_claims",
			Help: "The sidecar's Worker claims, one per VPC it serves, by state: ready, pending (Worker has " +
				"not finished programming, or reports Ready=False with the reason given), refused (Worker " +
				"refused the last call with the reason given, for example ClaimHeldByAnotherPod while the " +
				"proxy's previous pod runs), or unconfigured (the routed link's pod end is not configured yet).",
		}, []string{stateLabel, labels.Reason}),
		destinations: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "worker_destinations",
			Help: "Backends of the sidecar's claims by how Worker resolved them: local (routed over the " +
				"routed link), fabric (encapsulated by the sidecar's datapath) or unresolved.",
		}, []string{modeLabel}),
		operations: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "worker_claim_operations_total",
			Help: "Worker claim calls by operation (request, update, release, or reassert, the repeated " +
				"Request each sweep that recreates a claim Worker lost) and outcome: success, or the reason " +
				"Worker gave for refusing it.",
		}, []string{operationLabel, labels.Outcome}),
	}
	m.capabilities.Reset()
	m.claims.Reset()
	m.destinations.Reset()
	m.operations.Reset()
	m.connected.Set(0)
	return m
}

// SetConnected records whether a Worker session is open.
func (m *ClaimMetrics) SetConnected(up bool) {
	if m == nil {
		return
	}
	if up {
		m.connected.Set(1)
	} else {
		m.connected.Set(0)
	}
}

// SetCapabilities records the capabilities of a new session.
func (m *ClaimMetrics) SetCapabilities(caps []*workerv1alpha1.Capability) {
	if m == nil {
		return
	}
	m.capabilities.Reset()
	for _, c := range caps {
		state := "unavailable"
		if c.GetState() == workerv1alpha1.CapabilityState_CAPABILITY_STATE_AVAILABLE {
			state = "available"
		}
		m.capabilities.WithLabelValues(c.GetName(), state, c.GetReason()).Set(1)
	}
}

// operation counts one claim call.
func (m *ClaimMetrics) operation(op string, err error) {
	if m == nil || op == "" {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = workerclient.Reason(err)
		if outcome == "" {
			outcome = status.Code(err).String()
		}
	}
	m.operations.WithLabelValues(op, outcome).Inc()
}

// setClaims replaces the claim and destination counts.
func (m *ClaimMetrics) setClaims(states map[[2]string]int, modes map[string]int) {
	m.claims.Reset()
	for k, n := range states {
		m.claims.WithLabelValues(k[0], k[1]).Set(float64(n))
	}
	m.destinations.Reset()
	for _, mode := range []string{"local", "fabric", "unresolved"} {
		m.destinations.WithLabelValues(mode).Set(float64(modes[mode]))
	}
}
