// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
)

// Datapath checks each sweep makes: reading the shared eBPF datapath's
// generation, and reading back this sidecar's rows in its two registration
// maps (vrf_table and ifindex_vrf_table).
const (
	CheckGeneration       = "generation"
	CheckRegistrationRows = "registration_rows"
)

// checkLabel is the label naming a datapath check.
const checkLabel = "check"

// Check outcomes. unknown is only a status: nothing has been checked yet.
const (
	CheckUnknown = "unknown"
	CheckOK      = "ok"
	CheckMissing = "missing"
	CheckError   = "error"
)

// Why a reapply pass ran.
const (
	ReapplyGenerationChanged = "generation_changed"
	ReapplyRowsMissing       = "rows_missing"
	ReapplyRetry             = "retry"
)

var (
	datapathChecks = []string{CheckGeneration, CheckRegistrationRows}
	checkStatuses  = []string{CheckUnknown, CheckOK, CheckMissing, CheckError}
	// checkResults are the results each check can complete with: generation
	// has no missing outcome.
	checkResults = map[string][]string{
		CheckGeneration:       {CheckOK, CheckError},
		CheckRegistrationRows: {CheckOK, CheckMissing, CheckError},
	}
	reapplyReasons = []string{ReapplyGenerationChanged, ReapplyRowsMissing, ReapplyRetry}
	reapplyResults = []string{reapplySuccess, reapplyError}
)

// Reapply pass results.
const (
	reapplySuccess = "success"
	reapplyError   = "error"
)

// DatapathMetrics reports what each sweep's datapath checks found and why
// reapply passes ran, which the existing reapply_total cannot: a failed read
// is otherwise treated as fine for the purpose of deciding whether to repair,
// and looks the same as a healthy check. These checks cover the generation and
// the registration rows only, not every route, TC attachment or the return
// path. Every method is safe on a nil receiver.
type DatapathMetrics struct {
	checks        *prometheus.CounterVec
	status        *checkStatusCollector
	lastCompleted *prometheus.GaugeVec
	reapplies     *prometheus.CounterVec
	pending       prometheus.Gauge

	now func() time.Time
}

// NewDatapathMetrics creates datapath metrics on the instrumentation
// library's registry, every check's status unknown. The registry keeps the
// series across calls, so each call starts them over. MustRegister exports
// the check statuses.
func NewDatapathMetrics() *DatapathMetrics {
	m := &DatapathMetrics{
		checks: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "datapath_checks_total",
			Help: "Completed datapath checks, by check (generation, registration_rows) and result (ok, " +
				"missing for registration_rows, error when the read failed).",
		}, []string{checkLabel, resultLabel}),
		status: newCheckStatusCollector(),
		lastCompleted: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "datapath_check_last_completed_timestamp_seconds",
			Help:      "Unix time each check last completed, whatever its result; 0 before the first.",
		}, []string{checkLabel}),
		reapplies: metrics.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "datapath_reapply_total",
			Help: "Reapply passes over every tracked VRF and route, by reason (generation_changed, " +
				"rows_missing, retry of a failed pass) and result (success when every reapply succeeded).",
		}, []string{"reason", resultLabel}),
		pending: metrics.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "datapath_reapply_pending",
			Help:      "1 while a reapply pass left something unapplied, until a later pass succeeds.",
		}),
		now: time.Now,
	}
	m.checks.Reset()
	m.lastCompleted.Reset()
	m.reapplies.Reset()
	m.pending.Set(0)
	for _, check := range datapathChecks {
		m.lastCompleted.WithLabelValues(check)
		for _, result := range checkResults[check] {
			m.checks.WithLabelValues(check, result)
		}
	}
	for _, reason := range reapplyReasons {
		for _, result := range reapplyResults {
			m.reapplies.WithLabelValues(reason, result)
		}
	}
	return m
}

// MustRegister registers m's check status collector on the instrumentation
// library's registry. Call it once per process.
func (m *DatapathMetrics) MustRegister() {
	metrics.MustRegister(m.status)
}

// checked records a completed check of check with result. The counter,
// status and timestamp are updated separately; every caller holds the
// Store's lock, so writers never interleave.
func (m *DatapathMetrics) checked(check, result string) {
	if m == nil {
		return
	}
	m.checks.WithLabelValues(check, result).Inc()
	m.status.set(check, result)
	now := m.now()
	m.lastCompleted.WithLabelValues(check).Set(float64(now.Unix()) + float64(now.Nanosecond())/1e9)
}

// rowsNotChecked records that the registration rows were not read this sweep.
// A last outcome of ok becomes unknown, since it may no longer hold; missing
// and error stay, so a problem stays visible until a read replaces it. The
// counter and timestamp stay as they were.
func (m *DatapathMetrics) rowsNotChecked() {
	if m != nil {
		m.status.downgradeOK(CheckRegistrationRows)
	}
}

// reapplied records a completed reapply pass run for reason.
func (m *DatapathMetrics) reapplied(reason string, ok bool) {
	if m == nil {
		return
	}
	result := reapplySuccess
	if !ok {
		result = reapplyError
	}
	m.reapplies.WithLabelValues(reason, result).Inc()
}

// reapplyPending publishes whether a reapply is still owed.
func (m *DatapathMetrics) reapplyPending(pending bool) {
	if m == nil {
		return
	}
	v := 0.0
	if pending {
		v = 1
	}
	m.pending.Set(v)
}

var checkStatusDesc = prometheus.NewDesc(prometheus.BuildFQName(metricsNamespace, "", "datapath_check_status"),
	"1 for each datapath check's latest status, 0 for its others: unknown (not checked yet, or an ok "+
		"that could not be re-read this sweep), ok, missing (registration_rows only) or error (the read "+
		"failed, so the state is unknown, not healthy).",
	[]string{checkLabel, statusLabel}, nil)

// checkStatusCollector exports datapath_check_status from one snapshot taken
// under its own lock, so a scrape always sees exactly one status per check.
type checkStatusCollector struct {
	mu     sync.Mutex
	status map[string]string
}

func newCheckStatusCollector() *checkStatusCollector {
	c := &checkStatusCollector{status: map[string]string{}}
	for _, check := range datapathChecks {
		c.status[check] = CheckUnknown
	}
	return c
}

// downgradeOK makes check unknown if its status is ok.
func (c *checkStatusCollector) downgradeOK(check string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status[check] == CheckOK {
		c.status[check] = CheckUnknown
	}
}

func (c *checkStatusCollector) set(check, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status[check] = status
}

// Describe implements prometheus.Collector.
func (c *checkStatusCollector) Describe(ch chan<- *prometheus.Desc) { ch <- checkStatusDesc }

// Collect implements prometheus.Collector.
func (c *checkStatusCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	snapshot := make(map[string]string, len(c.status))
	for check, status := range c.status {
		snapshot[check] = status
	}
	c.mu.Unlock()
	for _, check := range datapathChecks {
		for _, status := range checkStatuses {
			v := 0.0
			if snapshot[check] == status {
				v = 1
			}
			ch <- prometheus.MustNewConstMetric(checkStatusDesc, prometheus.GaugeValue, v, check, status)
		}
	}
}
