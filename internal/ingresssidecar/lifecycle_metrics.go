// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Startup stages, in the order RunStartup runs them.
const (
	StageSeed      = "seed"
	StageInventory = "inventory"
	StagePrune     = "prune"
)

// Stage statuses. Each stage reports exactly one at a time.
const (
	StatusPending  = "pending"
	StatusRunning  = "running"
	StatusComplete = "complete"
	StatusFailed   = "failed"
	StatusSkipped  = "skipped"
)

// Attempt results.
const (
	ResultSuccess = "success"
	ResultError   = "error"
)

// Label names shared by the sidecar's metrics.
const (
	resultLabel = "result"
	statusLabel = "status"
)

var (
	startupStages   = []string{StageSeed, StageInventory, StagePrune}
	stageStatuses   = []string{StatusPending, StatusRunning, StatusComplete, StatusFailed, StatusSkipped}
	attemptResults  = []string{ResultSuccess, ResultError}
	sweepBucketsSec = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}
)

// LifecycleMetrics reports whether this sidecar finished starting up and
// whether its sweep is still making progress, which no existing gauge does: a
// sidecar stuck retrying its startup list, or whose sweep is blocked, still
// serves /metrics with its last values. Every method is safe on a nil
// receiver, so tests and callers without metrics pass nil.
//
// Instruments are updated where the work happens; a scrape only reads them.
type LifecycleMetrics struct {
	stageStatus   *stageCollector
	attempts      *prometheus.CounterVec
	complete      prometheus.Gauge
	sweepLast     prometheus.Gauge
	sweepDuration prometheus.Histogram
	sweepInterval prometheus.Gauge
	grace         prometheus.Gauge
	prunedRows    prometheus.Counter

	now func() time.Time
}

// NewLifecycleMetrics builds unregistered lifecycle metrics for a sidecar that
// sweeps every interval and delays teardown by grace, with every startup
// stage pending and no sweep completed.
func NewLifecycleMetrics(interval, grace time.Duration) *LifecycleMetrics {
	m := &LifecycleMetrics{
		stageStatus: newStageCollector(),
		attempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "startup_attempts_total",
			Help:      "Completed startup stage attempts, by stage and result (success, error).",
		}, []string{"stage", resultLabel}),
		complete: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "startup_complete",
			Help: "1 once the seed succeeded, inventory and prune were handled and the sweep started. " +
				"Startup procedure only: a failed inventory or prune still reports 1, and it says nothing " +
				"about routes or traffic.",
		}),
		sweepLast: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "sweep_last_completed_timestamp_seconds",
			Help:      "Unix time the last sweep finished, whatever its operations' results; 0 before the first.",
		}),
		sweepDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "sweep_duration_seconds",
			Help: "Time each sweep took, including waiting for the store's lock. A sweep outlasting the " +
				"interval absorbs the ticks it missed rather than queueing them.",
			Buckets: sweepBucketsSec,
		}),
		sweepInterval: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "sweep_interval_seconds",
			Help:      "Configured time between sweeps.",
		}),
		grace: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "teardown_grace_seconds",
			Help:      "Configured teardown grace period, applied to a route and then to its VRF.",
		}),
		prunedRows: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "pruned_rows_total",
			Help:      "Shared eBPF map rows the startup prune removed, including those removed before it failed.",
		}),
		now: time.Now,
	}
	for _, stage := range startupStages {
		for _, result := range attemptResults {
			m.attempts.WithLabelValues(stage, result)
		}
	}
	m.sweepInterval.Set(interval.Seconds())
	m.grace.Set(grace.Seconds())
	return m
}

// MustRegister registers every lifecycle metric against reg, panicking on a
// duplicate. Call it once per process.
func (m *LifecycleMetrics) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(m.stageStatus, m.attempts, m.complete, m.sweepLast, m.sweepDuration,
		m.sweepInterval, m.grace, m.prunedRows)
}

// setStage makes status the one current status of stage.
func (m *LifecycleMetrics) setStage(stage, status string) {
	if m == nil {
		return
	}
	m.stageStatus.set(stage, status)
}

var stageStatusDesc = prometheus.NewDesc(prometheus.BuildFQName(metricsNamespace, "", "startup_stage_status"),
	"1 for each startup stage's current status, 0 for its others. Stages: seed (list selected "+
		"EndpointSlices), inventory (adopt host state), prune (remove an earlier pod's eBPF rows). "+
		"Statuses: pending, running, complete, failed, skipped (prune after a failed inventory).",
	[]string{"stage", statusLabel}, nil)

// stageCollector exports startup_stage_status from one snapshot taken under
// its own lock, so a scrape always sees exactly one status per stage, never
// a stage caught between two.
type stageCollector struct {
	mu     sync.Mutex
	status map[string]string
}

func newStageCollector() *stageCollector {
	c := &stageCollector{status: map[string]string{}}
	for _, stage := range startupStages {
		c.status[stage] = StatusPending
	}
	return c
}

func (c *stageCollector) set(stage, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status[stage] = status
}

// Describe implements prometheus.Collector.
func (c *stageCollector) Describe(ch chan<- *prometheus.Desc) { ch <- stageStatusDesc }

// Collect implements prometheus.Collector.
func (c *stageCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	snapshot := make(map[string]string, len(c.status))
	for stage, status := range c.status {
		snapshot[stage] = status
	}
	c.mu.Unlock()
	for _, stage := range startupStages {
		for _, status := range stageStatuses {
			v := 0.0
			if snapshot[stage] == status {
				v = 1
			}
			ch <- prometheus.MustNewConstMetric(stageStatusDesc, prometheus.GaugeValue, v, stage, status)
		}
	}
}

// attempt records one completed attempt of stage and moves the stage to
// complete or failed.
func (m *LifecycleMetrics) attempt(stage string, err error) {
	if m == nil {
		return
	}
	if err != nil {
		m.attempts.WithLabelValues(stage, ResultError).Inc()
		m.setStage(stage, StatusFailed)
		return
	}
	m.attempts.WithLabelValues(stage, ResultSuccess).Inc()
	m.setStage(stage, StatusComplete)
}

func (m *LifecycleMetrics) startupComplete() {
	if m != nil {
		m.complete.Set(1)
	}
}

func (m *LifecycleMetrics) pruned(rows int) {
	if m != nil && rows > 0 {
		m.prunedRows.Add(float64(rows))
	}
}

// sweepStart returns the time a sweep starts, for sweepDone.
func (m *LifecycleMetrics) sweepStart() time.Time {
	if m == nil {
		return time.Time{}
	}
	return m.now()
}

// sweepDone records a sweep that started at start as completed now.
func (m *LifecycleMetrics) sweepDone(start time.Time) {
	if m == nil {
		return
	}
	end := m.now()
	m.sweepDuration.Observe(end.Sub(start).Seconds())
	m.sweepLast.Set(unixSeconds(end))
}

// unixSeconds is t as fractional Unix seconds, exact to the nanosecond for any
// time a sidecar sees.
func unixSeconds(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}
