// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/fabric/index"
)

// labelType is the query type label every per-request collector carries,
// and labelOutcome the label carrying an operation's outcome.
const (
	labelType    = "type"
	labelOutcome = "outcome"
)

// Metrics is the node sidecar's Prometheus instrumentation, on the
// instrumentation library's registry, which the sidecar serves with that
// library's metrics.Handler. Request IDs and targets are never labels.
type Metrics struct {
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
	permits         *prometheus.CounterVec
}

// NewMetrics creates Metrics on the instrumentation library's registry. The
// registry keeps the series across calls, so each call starts the vectors
// over.
func NewMetrics() *Metrics {
	m := &Metrics{
		requests: metrics.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_node_requests_total",
			Help: "Execute calls by query type and outcome (OK or the error code).",
		}, []string{labelType, labelOutcome}),
		duration: metrics.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "fabric_api_node_request_duration_seconds",
			Help:    "Execute call duration by query type, including queueing.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{labelType}),
		responseBytes: metrics.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "fabric_api_node_response_bytes",
			Help:    "Serialized Execute response size by query type.",
			Buckets: prometheus.ExponentialBuckets(256, 4, 8),
		}, []string{labelType}),
		truncated: metrics.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_node_truncated_responses_total",
			Help: "Responses shaped down to budget, by query type.",
		}, []string{labelType}),
		inFlight: metrics.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_node_in_flight_requests",
			Help: "Execute calls currently running or queued.",
		}),
		dedupHits: metrics.NewCounter(prometheus.CounterOpts{
			Name: "fabric_api_node_duplicate_requests_total",
			Help: "Execute calls answered from the duplicate-suppression cache.",
		}),
		dedupEntries: metrics.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_node_duplicate_cache_entries",
			Help: "Entries in the duplicate-suppression cache.",
		}),
		available: metrics.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_node_diagnostics_available",
			Help: "1 when FRR is reachable at a supported version and credentials are loaded.",
		}),
		frrInfo: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fabric_api_node_frr_info",
			Help: "FRR version last read from bgpd, and whether it is supported.",
		}, []string{"version", "supported"}),
		breakerOpen: metrics.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_node_expensive_breaker_open",
			Help: "1 while expensive searches are suspended after an uncertain timed-out scan.",
		}),
		probePackets: metrics.NewCounter(prometheus.CounterOpts{
			Name: "fabric_api_node_probe_packets_total",
			Help: "ICMP probe packets sent.",
		}),
		certExpiry: metrics.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_certificate_expiry_timestamp_seconds",
			Help: "NotAfter of the loaded mTLS certificate: the gateway's client certificate or the node's " +
				"serving certificate.",
		}),
		credentialsOK: metrics.NewGauge(prometheus.GaugeOpts{
			Name: "fabric_api_credentials_loaded",
			Help: "1 when valid mTLS credentials are loaded.",
		}),
		identityRefresh: metrics.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_node_identity_refreshes_total",
			Help: "Reads of FRR version, router ID and ASN, by outcome.",
		}, []string{labelOutcome}),
		permits: metrics.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_api_node_permits_total",
			Help: "Probe permits the node verified, by outcome: accepted, or why it refused one (invalid, " +
				"malformed, mismatch, expired, starting, clock, lease, epoch, replayed, full).",
		}, []string{labelOutcome}),
	}
	for _, v := range []interface{ Reset() }{m.requests, m.duration, m.responseBytes, m.truncated, m.frrInfo,
		m.identityRefresh, m.permits} {
		v.Reset()
	}
	return m
}

// The function metrics read their values through these sources. The library
// creates a function metric only once per process, while the Register
// methods can run again, as tests do: each creates its metrics on its first
// call and points them at the newest source on every call.
var (
	clockSource funcSource[func() error]
	indexSource funcSource[index.Index]
)

// funcSource holds the value a set of function metrics reads, and creates
// them the first time it is set.
type funcSource[T any] struct {
	create sync.Once
	v      atomic.Pointer[T]
}

// set makes v what the metrics read, creating them with create on the first
// call.
func (s *funcSource[T]) set(v *T, create func()) {
	s.v.Store(v)
	s.create.Do(create)
}

// get returns what the metrics read.
func (s *funcSource[T]) get() *T { return s.v.Load() }

// RegisterClock exports clock's health as fabric_api_node_clock_synchronized,
// read on every scrape. A node registers it only when it verifies probe
// permits, the one place it trusts its clock.
func (m *Metrics) RegisterClock(clock func() error) {
	clockSource.set(&clock, func() {
		metrics.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_node_clock_synchronized",
			Help: "1 while the kernel reports its clock synchronised within the permit bound; probe permits are " +
				"refused otherwise.",
		}, func() float64 { return boolGauge((*clockSource.get())() == nil) })
	})
}

// RegisterIndex exports the search index's state and counts the BMP
// messages applied to it.
func (m *Metrics) RegisterIndex(ix *index.Index) {
	m.bmpMessages = metrics.NewCounter(prometheus.CounterOpts{
		Name: "fabric_api_node_bmp_route_messages_total",
		Help: "BMP Loc-RIB route monitoring messages applied to the search index.",
	})
	indexSource.set(ix, createIndexMetrics)
}

// createIndexMetrics creates RegisterIndex's function metrics, reading
// indexSource.
func createIndexMetrics() {
	routes := func(afi string, v4 bool) {
		metrics.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fabric_api_node_search_index_routes", Help: "Prefixes in the search index.",
			ConstLabels: prometheus.Labels{"afi": afi},
		}, func() float64 {
			a, b, _, _ := indexSource.get().Stats()
			if v4 {
				return float64(a)
			}
			return float64(b)
		})
	}
	routes("ipv4", true)
	routes("ipv6", false)
	metrics.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "fabric_api_node_search_index_attribute_sets",
		Help: "Distinct path attribute sets the search index holds.",
	}, func() float64 { _, _, a, _ := indexSource.get().Stats(); return float64(a) })
	metrics.NewCounterFunc(prometheus.CounterOpts{
		Name: "fabric_api_node_search_index_overflow_total",
		Help: "Route announcements dropped because the search index was at its route ceiling.",
	}, func() float64 { _, _, _, o := indexSource.get().Stats(); return float64(o) })
	metrics.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "fabric_api_node_search_index_synced",
		Help: "1 when the search index holds bgpd's full table and follows it over BMP.",
	}, func() float64 { return boolGauge(indexSource.get().State().Synced) })
	metrics.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "fabric_api_node_search_index_last_update_timestamp_seconds",
		Help: "When the search index last applied a route change.",
	}, func() float64 {
		if t := indexSource.get().State().LastUpdate; !t.IsZero() {
			return float64(t.Unix())
		}
		return 0
	})
}

// BMPMessage counts one applied BMP route monitoring message. Only a node
// that called RegisterIndex counts them.
func (m *Metrics) BMPMessage() {
	if m.bmpMessages != nil {
		m.bmpMessages.Inc()
	}
}

// CertificateExpiry records a loaded certificate's expiry.
func (m *Metrics) CertificateExpiry(unix float64) { m.certExpiry.Set(unix) }
