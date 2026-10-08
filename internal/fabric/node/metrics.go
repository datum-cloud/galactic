// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go.datum.net/galactic/internal/fabric/index"
)

// labelType is the query type label every per-request collector carries.
const labelType = "type"

// Metrics is the node sidecar's Prometheus instrumentation in a private
// registry. Request IDs and targets are never labels.
type Metrics struct {
	Registry *prometheus.Registry

	requests        *prometheus.CounterVec
	duration        *prometheus.HistogramVec
	responseBytes   *prometheus.HistogramVec
	truncated       *prometheus.CounterVec
	inFlight        prometheus.Gauge
	dedupHits       prometheus.Counter
	dedupEntries    prometheus.Gauge
	available       prometheus.Gauge
	frrInfo         *prometheus.GaugeVec
	breakerOpen     prometheus.Gauge
	probePackets    prometheus.Counter
	certExpiry      prometheus.Gauge
	credentialsOK   prometheus.Gauge
	identityRefresh *prometheus.CounterVec
	bmpMessages     prometheus.Counter
}

// NewMetrics builds Metrics with every collector registered.
func NewMetrics() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_node_requests_total",
			Help: "Execute calls by query type and outcome (OK or the error code).",
		}, []string{labelType, "outcome"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "fabric_api_node_request_duration_seconds",
			Help:    "Execute call duration by query type, including queueing.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{labelType}),
		responseBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "fabric_api_node_response_bytes",
			Help:    "Serialized Execute response size by query type.",
			Buckets: prometheus.ExponentialBuckets(256, 4, 8),
		}, []string{labelType}),
		truncated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_node_truncated_responses_total",
			Help: "Responses shaped down to budget, by query type.",
		}, []string{labelType}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_node_in_flight_requests",
			Help: "Execute calls currently running or queued.",
		}),
		dedupHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fabric_api_node_duplicate_requests_total",
			Help: "Execute calls answered from the duplicate-suppression cache.",
		}),
		dedupEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_node_duplicate_cache_entries",
			Help: "Entries in the duplicate-suppression cache.",
		}),
		available: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_node_diagnostics_available",
			Help: "1 when FRR is reachable at a supported version and credentials are loaded.",
		}),
		frrInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fabric_api_node_frr_info",
			Help: "FRR version last read from bgpd, and whether it is supported.",
		}, []string{"version", "supported"}),
		breakerOpen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_node_expensive_breaker_open",
			Help: "1 while expensive searches are suspended after an uncertain timed-out scan.",
		}),
		probePackets: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fabric_api_node_probe_packets_total",
			Help: "ICMP probe packets sent.",
		}),
		certExpiry: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_certificate_expiry_timestamp_seconds",
			Help: "NotAfter of the loaded serving certificate.",
		}),
		credentialsOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_credentials_loaded",
			Help: "1 when valid mTLS credentials are loaded.",
		}),
		bmpMessages: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fabric_api_node_bmp_route_messages_total",
			Help: "BMP Loc-RIB route monitoring messages applied to the search index.",
		}),
		identityRefresh: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_node_identity_refreshes_total",
			Help: "Reads of FRR version, router ID and ASN, by outcome.",
		}, []string{"outcome"}),
	}
	m.Registry.MustRegister(m.requests, m.duration, m.responseBytes, m.truncated, m.inFlight, m.dedupHits,
		m.dedupEntries, m.available, m.frrInfo, m.breakerOpen, m.probePackets, m.certExpiry, m.credentialsOK,
		m.identityRefresh, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves the registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

// RegisterIndex adds the search index's state to the registry.
func (m *Metrics) RegisterIndex(ix *index.Index) {
	routes := func(v4 bool) func() float64 {
		return func() float64 {
			a, b, _, _ := ix.Stats()
			if v4 {
				return float64(a)
			}
			return float64(b)
		}
	}
	m.Registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_node_search_index_routes", Help: "Prefixes in the search index.",
			ConstLabels: prometheus.Labels{"afi": "ipv4"},
		}, routes(true)),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_node_search_index_routes", Help: "Prefixes in the search index.",
			ConstLabels: prometheus.Labels{"afi": "ipv6"},
		}, routes(false)),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_node_search_index_attribute_sets",
			Help: "Distinct path attribute sets the search index holds.",
		}, func() float64 { _, _, a, _ := ix.Stats(); return float64(a) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "fabric_api_node_search_index_overflow_total",
			Help: "Route announcements dropped because the search index was at its route ceiling.",
		}, func() float64 { _, _, _, o := ix.Stats(); return float64(o) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_node_search_index_synced",
			Help: "1 when the search index holds bgpd's full table and follows it over BMP.",
		}, func() float64 { return boolGauge(ix.State().Synced) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_node_search_index_last_update_timestamp_seconds",
			Help: "When the search index last applied a route change.",
		}, func() float64 {
			if t := ix.State().LastUpdate; !t.IsZero() {
				return float64(t.Unix())
			}
			return 0
		}),
		m.bmpMessages,
	)
}

// BMPMessage counts one applied BMP route monitoring message.
func (m *Metrics) BMPMessage() { m.bmpMessages.Inc() }

// CertificateExpiry records a loaded certificate's expiry.
func (m *Metrics) CertificateExpiry(unix float64) { m.certExpiry.Set(unix) }
