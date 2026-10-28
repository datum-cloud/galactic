// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	instmetrics "go.miloapis.com/instrumentation/metrics"
)

// sidecarReturnNamespace and sidecarReturnSubsystem name galactic-cni's series
// for the ingress sidecar's host-side return path, galactic_sidecar_return_*.
const (
	sidecarReturnNamespace = "galactic"
	sidecarReturnSubsystem = "sidecar_return"
)

// The outcome of one sidecar return path pass, as reconcile_total counts it.
const (
	// SidecarReturnSuccess: every advertised endpoint is installed, or there
	// is none, and stale routes were pruned.
	SidecarReturnSuccess = "success"
	// SidecarReturnPartial: the pass ran, but at least one endpoint failed to
	// install or the prune failed.
	SidecarReturnPartial = "partial"
	// SidecarReturnWaitingIdentity: endpoints are advertised, but this node's
	// BGPRouter has no SRv6 locator yet, so none could be installed.
	SidecarReturnWaitingIdentity = "waiting_identity"
	// SidecarReturnError: the pass could not list the advertisements, read
	// the node's identity, or open or register the node in the datapath maps.
	SidecarReturnError = "error"
)

// The steps of a sidecar return path pass, as operations_total counts them.
const (
	// SidecarReturnOpInstall installs one endpoint: route, neighbor and
	// vrf_table entry.
	SidecarReturnOpInstall = "install"
	// SidecarReturnOpRegister opens the datapath maps and registers this
	// node's locator and function entries, once per pass with endpoints.
	SidecarReturnOpRegister = "register"
	// SidecarReturnOpPrune removes return routes no endpoint accounts for.
	SidecarReturnOpPrune = "prune"
	// SidecarReturnOpReap removes what a deleted sidecar pod left behind.
	SidecarReturnOpReap = "reap"
)

var (
	sidecarReturnResults = []string{
		SidecarReturnSuccess, SidecarReturnPartial, SidecarReturnWaitingIdentity, SidecarReturnError,
	}
	sidecarReturnOps = []string{
		SidecarReturnOpInstall, SidecarReturnOpRegister, SidecarReturnOpPrune, SidecarReturnOpReap,
	}
)

// SidecarReturn reports the host side of the ingress sidecar's return path:
// how many advertised gateway endpoints this node wants, how many the last
// pass installed, how each pass ended and when, and every step's outcome.
//
// A pass that cannot list the advertisements leaves the endpoint counts and
// the timestamp as they were, so a stalled or failing discovery shows as an
// ageing timestamp rather than as a healthy empty node.
//
// The endpoint counts and the timestamp are published together as one
// snapshot, so a scrape never sees applied and pending from different passes.
// The installer runs one pass at a time, so updates are never reordered. All
// methods are safe on a nil receiver, which tests use.
type SidecarReturn struct {
	snapshot   *sidecarReturnSnapshot
	reconciles *prometheus.CounterVec
	operations *prometheus.CounterVec
}

// sidecarReturnPass is what the last pass that listed the advertisements
// found. The zero value is the state before the first.
type sidecarReturnPass struct {
	desired, applied int
	completed        time.Time
}

// sidecarReturnSnapshot exports the last pass's endpoint counts and time from
// one atomically published value.
type sidecarReturnSnapshot struct {
	last      atomic.Pointer[sidecarReturnPass]
	endpoints *prometheus.Desc
	completed *prometheus.Desc
}

func (c *sidecarReturnSnapshot) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.endpoints
	ch <- c.completed
}

func (c *sidecarReturnSnapshot) Collect(ch chan<- prometheus.Metric) {
	p := c.last.Load()
	ch <- prometheus.MustNewConstMetric(c.endpoints, prometheus.GaugeValue, float64(p.desired), "desired")
	ch <- prometheus.MustNewConstMetric(c.endpoints, prometheus.GaugeValue, float64(p.applied), "applied")
	ch <- prometheus.MustNewConstMetric(c.endpoints, prometheus.GaugeValue,
		float64(p.desired-p.applied), "pending")
	ts := 0.0
	if !p.completed.IsZero() {
		ts = float64(p.completed.UnixNano()) / 1e9
	}
	ch <- prometheus.MustNewConstMetric(c.completed, prometheus.GaugeValue, ts)
}

// sidecarReturnPasses is the snapshot every SidecarReturn reports through.
// A collector can be registered only once, so it is shared, and registered by
// the first NewSidecarReturn.
var (
	sidecarReturnPasses = &sidecarReturnSnapshot{
		endpoints: prometheus.NewDesc(
			prometheus.BuildFQName(sidecarReturnNamespace, sidecarReturnSubsystem, "endpoints"),
			"Ingress sidecar gateway endpoints on this node as of the last pass that listed them: desired "+
				"(advertised), applied (installed by that pass) and pending (not installed). applied and pending "+
				"partition desired.",
			[]string{"state"}, nil),
		completed: prometheus.NewDesc(
			prometheus.BuildFQName(sidecarReturnNamespace, sidecarReturnSubsystem, "last_completed_timestamp_seconds"),
			"Unix time of the last sidecar return path pass that listed the advertisements, whatever its "+
				"result; 0 before the first.",
			nil, nil),
	}
	registerSidecarReturnPasses sync.Once
)

// NewSidecarReturn creates the series on the instrumentation library's
// registry. The endpoint snapshot is process-wide and starts over with each
// call, so a process builds one SidecarReturn.
func NewSidecarReturn() *SidecarReturn {
	registerSidecarReturnPasses.Do(func() { instmetrics.MustRegister(sidecarReturnPasses) })
	sidecarReturnPasses.last.Store(&sidecarReturnPass{})
	m := &SidecarReturn{
		snapshot: sidecarReturnPasses,
		reconciles: instmetrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: sidecarReturnNamespace, Subsystem: sidecarReturnSubsystem, Name: "reconcile_total",
			Help: "Sidecar return path passes by result: success, partial (an endpoint or the prune failed), " +
				"waiting_identity (no SRv6 locator for this node yet) or error (nothing could be installed).",
		}, []string{"result"}),
		operations: instmetrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: sidecarReturnNamespace, Subsystem: sidecarReturnSubsystem, Name: "operations_total",
			Help: "Sidecar return path steps by operation (install per endpoint, register per pass, prune, reap) " +
				"and result (success, error).",
		}, []string{"operation", "result"}),
	}
	for _, r := range sidecarReturnResults {
		m.reconciles.WithLabelValues(r)
	}
	for _, op := range sidecarReturnOps {
		m.operations.WithLabelValues(op, "success")
		m.operations.WithLabelValues(op, "error")
	}
	return m
}

// Operation counts one step's outcome.
func (m *SidecarReturn) Operation(op string, err error) {
	if m == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	m.operations.WithLabelValues(op, result).Inc()
}

// Completed records a pass that listed desired endpoints, applied of which it
// installed, ending with result at.
func (m *SidecarReturn) Completed(at time.Time, result string, desired, applied int) {
	if m == nil {
		return
	}
	m.snapshot.last.Store(&sidecarReturnPass{desired: desired, applied: applied, completed: at})
	m.reconciles.WithLabelValues(result).Inc()
}

// DiscoveryFailed records a pass that could not list the advertisements. It
// leaves the endpoint counts and the timestamp from the last pass that did.
func (m *SidecarReturn) DiscoveryFailed() {
	if m == nil {
		return
	}
	m.reconciles.WithLabelValues(SidecarReturnError).Inc()
}
