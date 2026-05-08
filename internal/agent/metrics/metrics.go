// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics exposes Prometheus gauges and counters describing the
// agent's BGP session state, reconciler queue depths, and kernel route
// counts. Wired into a /metrics endpoint by the agent main.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics is the typed view of the agent's exported metrics. One
// instance per agent process.
type Metrics struct {
	// BGPSessionState is keyed by peer address. Value: 0=Idle,
	// 1=Connect, 2=Active, 3=OpenSent, 4=OpenConfirm, 5=Established.
	// Numeric values match internal/agent/bgp.SessionState.
	BGPSessionState *prometheus.GaugeVec

	// PendingAttachments tracks how many CNI Register events are
	// awaiting a matching VPCAttachment status update.
	PendingAttachments prometheus.Gauge

	// OriginatedPaths is the count of paths this agent currently
	// advertises into the BGP fabric.
	OriginatedPaths prometheus.Gauge

	// ReceivedPaths is the count of remote VPN paths the agent has
	// in its inbound BGP cache (regardless of whether they're
	// programmed to the kernel).
	ReceivedPaths prometheus.Gauge

	// KernelRoutesProgrammed is the count of remote pod routes
	// currently installed in node VRFs.
	KernelRoutesProgrammed prometheus.Gauge
}

// New constructs and registers the metrics with the given Registerer.
// Pass prometheus.DefaultRegisterer for the default Prometheus
// scrape endpoint.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		BGPSessionState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "galactic_agent",
			Name:      "bgp_session_state",
			Help:      "BGP FSM state per configured peer. 0=Idle..5=Established.",
		}, []string{"peer"}),
		PendingAttachments: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "galactic_agent",
			Name:      "pending_attachments",
			Help:      "CNI Register events awaiting matching VPCAttachment status.",
		}),
		OriginatedPaths: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "galactic_agent",
			Name:      "originated_paths",
			Help:      "BGP paths currently advertised by this agent.",
		}),
		ReceivedPaths: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "galactic_agent",
			Name:      "received_paths",
			Help:      "Remote VPN paths in the agent's inbound cache.",
		}),
		KernelRoutesProgrammed: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "galactic_agent",
			Name:      "kernel_routes_programmed",
			Help:      "Remote pod routes installed in local VRFs.",
		}),
	}
	for _, c := range []prometheus.Collector{
		m.BGPSessionState,
		m.PendingAttachments,
		m.OriginatedPaths,
		m.ReceivedPaths,
		m.KernelRoutesProgrammed,
	} {
		reg.MustRegister(c)
	}
	return m
}
