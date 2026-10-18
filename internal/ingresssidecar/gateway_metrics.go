// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// A desired VRF's return-path gateway state, as gateway_vrfs counts them.
// published is local publication of the BGPAdvertisement only: it does not
// mean the route has reached any peer.
const (
	GatewayAwaitingAddress     = "awaiting_address"
	GatewayAwaitingPublication = "awaiting_publication"
	GatewayPublished           = "published"
)

// Gateway operations and their results.
const (
	GatewayOpResolve  = "resolve"
	GatewayOpPublish  = "publish"
	GatewayOpWithdraw = "withdraw"

	GatewaySuccess        = "success"
	GatewayError          = "error"
	GatewayNotProvisioned = "not_provisioned"
)

var (
	gatewayStates = []string{GatewayAwaitingAddress, GatewayAwaitingPublication, GatewayPublished}
	gatewayOps    = map[string][]string{
		GatewayOpResolve:  {GatewaySuccess, GatewayError, GatewayNotProvisioned},
		GatewayOpPublish:  {GatewaySuccess, GatewayError},
		GatewayOpWithdraw: {GatewaySuccess, GatewayError},
	}
)

// GatewayMetrics reports whether return-path gateway publication is enabled,
// where each desired VRF's publication stands, how long the oldest has been
// waiting, and every resolve, publish and withdraw, including the failures
// the Store logs and otherwise forgets. The Store updates them under its own
// lock at each change; a scrape only reads them. Every method is safe on a
// nil receiver.
type GatewayMetrics struct {
	publicationEnabled       prometheus.Gauge
	addressAssignmentEnabled prometheus.Gauge
	vrfs                     *prometheus.GaugeVec
	oldest                   prometheus.Gauge
	operations               *prometheus.CounterVec

	now func() time.Time
}

// NewGatewayMetrics builds unregistered gateway metrics for a sidecar whose
// gateway publication and gateway address assignment are enabled as given.
func NewGatewayMetrics(publicationEnabled, addressAssignmentEnabled bool) *GatewayMetrics {
	m := &GatewayMetrics{
		publicationEnabled: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "gateway_publication_enabled",
			Help:      "1 when this sidecar publishes a return-path gateway advertisement per VPC.",
		}),
		addressAssignmentEnabled: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "gateway_address_assignment_enabled",
			Help:      "1 when this sidecar assigns each VPC's gateway address itself, from its gateway prefix.",
		}),
		vrfs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "gateway_vrfs",
			Help: "Installed, non-draining VRFs by return-path gateway state: awaiting_address, " +
				"awaiting_publication, or published (locally, not proof any peer has the route). " +
				"All zero while publication is disabled.",
		}, []string{"state"}),
		oldest: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "gateway_oldest_pending_timestamp_seconds",
			Help: "Unix time the longest-unpublished desired VRF started waiting; 0 when none is waiting. " +
				"Retries do not reset it.",
		}),
		operations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "gateway_operations_total",
			Help: "Gateway operations by operation and result: resolve (success, error, not_provisioned), " +
				"publish and withdraw (success, error).",
		}, []string{"operation", resultLabel}),
		now: time.Now,
	}
	m.publicationEnabled.Set(boolGauge(publicationEnabled))
	m.addressAssignmentEnabled.Set(boolGauge(addressAssignmentEnabled))
	for _, s := range gatewayStates {
		m.vrfs.WithLabelValues(s)
	}
	for op, results := range gatewayOps {
		for _, r := range results {
			m.operations.WithLabelValues(op, r)
		}
	}
	return m
}

// MustRegister registers every gateway metric against reg, panicking on a
// duplicate. Call it once per process.
func (m *GatewayMetrics) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(m.publicationEnabled, m.addressAssignmentEnabled, m.vrfs, m.oldest, m.operations)
}

func (m *GatewayMetrics) operation(op, result string) {
	if m != nil {
		m.operations.WithLabelValues(op, result).Inc()
	}
}

// clock is the time a VRF starts waiting.
func (m *GatewayMetrics) clock() time.Time {
	if m == nil {
		return time.Now()
	}
	return m.now()
}

// publish publishes each state's VRF count and the oldest wait's start, the
// zero Time when none is waiting.
func (m *GatewayMetrics) publish(counts map[string]int, oldest time.Time) {
	if m == nil {
		return
	}
	for _, s := range gatewayStates {
		m.vrfs.WithLabelValues(s).Set(float64(counts[s]))
	}
	if oldest.IsZero() {
		m.oldest.Set(0)
		return
	}
	m.oldest.Set(float64(oldest.Unix()) + float64(oldest.Nanosecond())/1e9)
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
