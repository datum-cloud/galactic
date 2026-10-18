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
	// OutcomeError is an activation that stopped on an error the agent
	// retries, such as a revision that failed validation or an
	// unwritable journal.
	OutcomeError = "error"
)

// Staging results the agent counts.
const (
	StageStaged           = "staged"
	StageRejected         = "rejected"
	StageRevisionNotFound = "revision_not_found"
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
// instrumentation. Register it on the registry the watch container serves.
type AgentMetrics struct {
	activations *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	staging     *prometheus.CounterVec
	lockWait    *prometheus.HistogramVec
	boot        *prometheus.GaugeVec
}

// NewAgentMetrics builds the agent's metrics and registers them on reg.
func NewAgentMetrics(reg prometheus.Registerer) *AgentMetrics {
	m := &AgentMetrics{
		activations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_router_activations_total",
			Help: "Activation epochs by outcome: committed, recovered, degraded, refused or error. Each epoch " +
				"counts at most once per outcome.",
		}, []string{"outcome"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "fabric_router_activation_duration_seconds",
			Help: "Time the agent took to commit, recover or degrade an activation, its stabilization window " +
				"included.",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1200, 1800, 3600},
		}, []string{"outcome"}),
		staging: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fabric_router_staging_runs_total",
			Help: "Candidate revisions the agent validated and diffed without applying, by result: staged, " +
				"rejected or revision_not_found.",
		}, []string{"result"}),
		lockWait: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "fabric_router_writer_lock_wait_seconds",
			Help:    "Time each FRR writer waited for the node's writer lock.",
			Buckets: []float64{.001, .01, .1, .5, 1, 5, 10, 30, 60, 120, 300, 900},
		}, []string{"writer"}),
		boot: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fabric_router_boot_source",
			Help: "1 for where the pod's init container took the configuration FRR started with: configmap, " +
				"checkpoint_offline, checkpoint_online or active_revision.",
		}, []string{"source"}),
	}
	reg.MustRegister(m.activations, m.duration, m.staging, m.lockWait, m.boot)
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

// Lock acquires the wrapped lock, recording the wait once it holds it.
func (l TimedLock) Lock(ctx context.Context) (func(), error) {
	start := time.Now()
	unlock, err := l.Locker.Lock(ctx)
	if err == nil && l.Metrics != nil {
		l.Metrics.lockWait.WithLabelValues(l.Writer).Observe(time.Since(start).Seconds())
	}
	return unlock, err
}

// activationCounter counts each epoch's outcomes once, although the agent
// sees a finished or refused epoch again on every sync.
type activationCounter struct {
	key     string
	counted map[string]bool
}

// count records outcome for the deployment's epoch, and the activation's
// duration when it ran, unless the epoch was already counted with it.
func (d *DeploymentAgent) count(uid string, epoch int64, outcome string, took time.Duration) {
	if d.Metrics == nil {
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
