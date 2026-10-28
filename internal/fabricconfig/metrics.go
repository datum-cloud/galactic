// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"
)

// Activation outcomes the agent counts.
const (
	OutcomeCommitted = "committed"
	OutcomeRecovered = "recovered"
	OutcomeDegraded  = "degraded"
	// OutcomeRefused is a promotion the agent will never activate: its
	// authorization does not cover it, or the activator refused it as
	// stale, mismatched or conflicting.
	OutcomeRefused = "refused"
	// OutcomeError is an activation attempt that stopped on an error the
	// agent retries, such as a revision that failed validation or an
	// unwritable journal. Unlike the other outcomes it counts every
	// attempt, so its rate shows the retries.
	OutcomeError = "error"
)

// Staging results the agent counts.
const (
	StageStaged           = "staged"
	StageRejected         = "rejected"
	StageRevisionNotFound = "revision_not_found"
)

// Results of waiting for the node's writer lock.
const (
	LockAcquired = "acquired"
	// LockTimeout is a wait its context's deadline ended.
	LockTimeout = "timeout"
	// LockError is any other failure: the writer shutting down, or the
	// lock file unusable.
	LockError = "error"
)

// Writers of FRR whose wait for the node's writer lock is measured.
const (
	WriterConfigMap  = "configmap"
	WriterDeployment = "deployment"
	WriterActivation = "activation"
	WriterNextHop    = "nexthop"
)

// BootSource is where the init container took the configuration FRR
// started with.
type BootSource string

const (
	// BootConfigMap is the node's ConfigMap.
	BootConfigMap BootSource = "configmap"
	// BootCheckpointOffline is the committed checkpoint, restored under
	// its offline boot authorization.
	BootCheckpointOffline BootSource = "checkpoint_offline"
	// BootCheckpointOnline is the committed checkpoint, restored after the
	// API confirmed the deployment still owns it.
	BootCheckpointOnline BootSource = "checkpoint_online"
	// BootActiveRevision is the deployment's active revision, read from
	// the API.
	BootActiveRevision BootSource = "active_revision"
)

// DefaultBootRecord is where the init container records its boot, in the
// pod-scoped /run/frr the watch container shares: it lasts as long as the
// pod, as the boot it describes does.
const DefaultBootRecord = "/run/frr/fabric-boot.json"

// BootRecord is what the init container started FRR with.
type BootRecord struct {
	Source BootSource `json:"source"`
	Reason string     `json:"reason,omitempty"`
}

// ClearBootRecord removes the record at path, so an earlier boot's record
// in the same pod is never exported as a later boot's. A missing record is
// not an error.
func ClearBootRecord(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove boot record: %w", err)
	}
	return nil
}

// WriteBootRecord writes rec to path, replacing any earlier record.
func WriteBootRecord(path string, rec BootRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // read by the pod's other containers
		return fmt.Errorf("write boot record: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write boot record: %w", err)
	}
	return nil
}

// ReadBootRecord reads the record at path. A missing record returns
// os.ErrNotExist.
func ReadBootRecord(path string) (BootRecord, error) {
	var rec BootRecord
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, fmt.Errorf("parse boot record %s: %w", path, err)
	}
	return rec, nil
}

// AgentMetrics is the activation path's and the writer lock's
// instrumentation.
type AgentMetrics struct {
	activations *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	staging     *prometheus.CounterVec
	lockWait    *prometheus.HistogramVec
	boot        *prometheus.GaugeVec
}

// NewAgentMetrics creates the agent's metrics on the instrumentation
// library's registry. The registry keeps the series across calls, so each
// call starts them over.
func NewAgentMetrics() *AgentMetrics {
	m := &AgentMetrics{
		activations: metrics.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_router_activations_total",
			Help: "Activations by outcome. committed, recovered, degraded and refused count each epoch once " +
				"per agent process, so a restarted agent may count an epoch it meets again; error counts every " +
				"failed attempt.",
		}, []string{"outcome"}),
		duration: metrics.NewHistogramVec(prometheus.HistogramOpts{
			Name: "fabric_router_activation_duration_seconds",
			Help: "Time the agent took to commit, recover or degrade an activation, its stabilization window " +
				"included.",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1200, 1800, 3600},
		}, []string{"outcome"}),
		staging: metrics.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_router_staging_runs_total",
			Help: "Candidate revisions the agent validated and diffed without applying, by result: staged, " +
				"rejected or revision_not_found.",
		}, []string{"result"}),
		lockWait: metrics.NewHistogramVec(prometheus.HistogramOpts{
			Name: "fabric_router_writer_lock_wait_seconds",
			Help: "Time each FRR writer waited for the node's writer lock, by result: acquired, timeout or " +
				"error. The lock is retried every 100ms.",
			Buckets: []float64{.1, .5, 1, 5, 10, 30, 60, 120, 300, 900},
		}, []string{"writer", "result"}),
		boot: metrics.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fabric_router_boot_source",
			Help: "1 for where the pod's init container took the configuration FRR started with: configmap, " +
				"checkpoint_offline, checkpoint_online or active_revision.",
		}, []string{"source"}),
	}
	m.activations.Reset()
	m.duration.Reset()
	m.staging.Reset()
	m.lockWait.Reset()
	m.boot.Reset()
	return m
}

// SetBoot records the pod's boot source.
func (m *AgentMetrics) SetBoot(s BootSource) {
	m.boot.Reset()
	m.boot.WithLabelValues(string(s)).Set(1)
}

// TimedLock is a Locker that observes how long each acquisition waited.
type TimedLock struct {
	Locker  Locker
	Metrics *AgentMetrics
	// Writer labels the observations.
	Writer string
}

// Lock acquires the wrapped lock, recording the wait and how it ended.
func (l TimedLock) Lock(ctx context.Context) (func(), error) {
	start := time.Now()
	unlock, err := l.Locker.Lock(ctx)
	if l.Metrics != nil {
		result := LockAcquired
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			result = LockTimeout
		case err != nil:
			result = LockError
		}
		l.Metrics.lockWait.WithLabelValues(l.Writer, result).Observe(time.Since(start).Seconds())
	}
	return unlock, err
}

// activationCounter counts each epoch's outcomes once in this process,
// although the agent sees a finished or refused epoch again on every sync.
type activationCounter struct {
	key     string
	counted map[string]bool
}

// count records outcome for the deployment's epoch, and the activation's
// duration when it ran, unless this process already counted the epoch
// with it. OutcomeError counts every call.
func (d *DeploymentAgent) count(uid string, epoch int64, outcome string, took time.Duration) {
	if d.Metrics == nil {
		return
	}
	if outcome == OutcomeError {
		d.Metrics.activations.WithLabelValues(outcome).Inc()
		return
	}
	key := fmt.Sprintf("%s/%d", uid, epoch)
	if d.counter.key != key {
		d.counter = activationCounter{key: key, counted: map[string]bool{}}
	}
	if d.counter.counted[outcome] {
		return
	}
	d.counter.counted[outcome] = true
	d.Metrics.activations.WithLabelValues(outcome).Inc()
	if took > 0 {
		d.Metrics.duration.WithLabelValues(outcome).Observe(took.Seconds())
	}
}

// countStage records one staging run.
func (d *DeploymentAgent) countStage(result string) {
	if d.Metrics != nil {
		d.Metrics.staging.WithLabelValues(result).Inc()
	}
}

// errorOutcome classifies an activation error: a refusal the agent will
// meet again unchanged, or an error it retries.
func errorOutcome(err error) string {
	if errors.Is(err, errRefused) || activationReason(err) != reasonRejected {
		return OutcomeRefused
	}
	return OutcomeError
}
