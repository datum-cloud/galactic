// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabricconfig/activation"
)

// requiredPeer is the fake router's only peer.
const requiredPeer = "203.0.113.1"

func activations(m *AgentMetrics, outcome string) float64 {
	return testutil.ToFloat64(m.activations.WithLabelValues(outcome))
}

// TestAgentMetricsActivations counts each epoch's outcome once, however
// often the agent sees the epoch again.
func TestAgentMetricsActivations(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceCRD))
	m := NewAgentMetrics(prometheus.NewRegistry())
	h.agent.Metrics = m
	if err := h.client.Create(context.Background(), release(h.revs[0], h.revs[1])); err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{}
	check := func(step string) {
		t.Helper()
		for _, o := range []string{OutcomeCommitted, OutcomeRecovered, OutcomeDegraded, OutcomeRefused, OutcomeError} {
			if got := activations(m, o); got != want[o] {
				t.Errorf("%s: activations{outcome=%q} = %v, want %v", step, o, got, want[o])
			}
		}
	}

	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 1, h.revs[0]) })
	h.sync()
	h.sync()
	want[OutcomeCommitted] = 1
	check("epoch 1 committed, synced twice")

	h.frr.peerState = "Active"
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		promote(d, 2, h.revs[1])
		d.Spec.Activation.RequiredPeers = []string{requiredPeer}
		d.Spec.Recovery = &networkv1alpha1.FabricRecovery{
			TargetRevisionRef:      &networkv1alpha1.LocalObjectRef{Name: h.revs[0].Name},
			TargetDependencyDigest: h.revs[0].Spec.ActivationDependencyDigest,
		}
	})
	h.sync()
	want[OutcomeRecovered] = 1
	check("epoch 2 recovered")

	// No recovery target: the epoch degrades, and every later sync meets
	// it again as an already failed epoch, which is not a new outcome.
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		promote(d, 3, h.revs[0])
		d.Spec.Activation.RequiredPeers = []string{requiredPeer}
		d.Spec.Recovery = nil
	})
	h.sync()
	h.sync()
	h.sync()
	want[OutcomeDegraded] = 1
	check("epoch 3 degraded, synced three times")

	// The release does not cover revs[2]: refused for good, counted once.
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) { promote(d, 4, h.revs[2]) })
	h.sync()
	h.sync()
	want[OutcomeRefused] = 1
	check("epoch 4 refused, synced twice")

	if n := testutil.CollectAndCount(m.duration); n != 3 {
		t.Errorf("duration has %d outcome series, want committed, recovered and degraded", n)
	}
	if n := testutil.CollectAndCount(m.lockWait); n != 0 {
		t.Errorf("the harness's agent has no timed lock, yet %d lock waits were observed", n)
	}
}

func TestErrorOutcome(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"PromotionRefused", fmt.Errorf("%w: release gone", errRefused), OutcomeRefused},
		{"Stale", fmt.Errorf("%w: epoch 1 below 2", activation.ErrStale), OutcomeRefused},
		{"DigestMismatch", activation.ErrDigestMismatch, OutcomeRefused},
		{"RecoveryConflict", activation.ErrRecoveryConflict, OutcomeRefused},
		{"IdentityMismatch", activation.ErrIdentityMismatch, OutcomeRefused},
		{"ValidationFailed", errors.New("revision x fails validation: exit 1"), OutcomeError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errorOutcome(tt.err); got != tt.want {
				t.Errorf("errorOutcome(%v) = %s, want %s", tt.err, got, tt.want)
			}
		})
	}
}

// TestAgentMetricsStaging counts a staging run each time the agent
// validates a candidate, not each sync that finds it already staged.
func TestAgentMetricsStaging(t *testing.T) {
	h := newHarness(t, deployment(networkv1alpha1.FabricConfigSourceShadow))
	m := NewAgentMetrics(prometheus.NewRegistry())
	h.agent.Metrics = m
	h.frr.running = rendered(t, h.revs[0])
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		d.Spec.CandidateRevisionRef = &networkv1alpha1.LocalObjectRef{Name: h.revs[1].Name}
	})
	h.sync()
	h.sync()
	if got := testutil.ToFloat64(m.staging.WithLabelValues(StageStaged)); got != 1 {
		t.Errorf("staged runs = %v after staging one candidate, want 1", got)
	}
	h.update(func(d *networkv1alpha1.FabricRouterDeployment) {
		d.Spec.CandidateRevisionRef = &networkv1alpha1.LocalObjectRef{Name: "missing"}
	})
	h.sync()
	if got := testutil.ToFloat64(m.staging.WithLabelValues(StageRevisionNotFound)); got != 1 {
		t.Errorf("revision_not_found runs = %v, want 1", got)
	}
}

type slowLock struct {
	wait time.Duration
	err  error
}

func (l slowLock) Lock(context.Context) (func(), error) {
	time.Sleep(l.wait)
	if l.err != nil {
		return nil, l.err
	}
	return func() {}, nil
}

// TestTimedLock observes every wait under its writer and how it ended:
// acquired, ended by its deadline, or failed otherwise.
func TestTimedLock(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg)
	for _, l := range []struct {
		writer string
		err    error
	}{
		{WriterActivation, nil},
		{WriterDeployment, context.DeadlineExceeded},
		{WriterNextHop, context.Canceled},
	} {
		lock := TimedLock{Locker: slowLock{wait: 20 * time.Millisecond, err: l.err}, Metrics: m, Writer: l.writer}
		unlock, err := lock.Lock(context.Background())
		if !errors.Is(err, l.err) {
			t.Fatalf("Lock = %v, want the wrapped lock's %v", err, l.err)
		}
		if err == nil {
			unlock()
		}
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var waits []string
	for _, f := range families {
		if f.GetName() != "fabric_router_writer_lock_wait_seconds" {
			continue
		}
		for _, s := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range s.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			h := s.GetHistogram()
			waits = append(waits, fmt.Sprintf("%s/%s=%d", labels["writer"], labels["result"], h.GetSampleCount()))
			if h.GetSampleSum() < 0.02 {
				t.Errorf("observed %vs, want at least the 20ms the lock took", h.GetSampleSum())
			}
		}
	}
	sort.Strings(waits)
	want := "activation/acquired=1,deployment/timeout=1,nexthop/error=1"
	if got := strings.Join(waits, ","); got != want {
		t.Errorf("lock waits = %q, want %q", got, want)
	}
}

// TestActivationCounterOnce counts a finished or refused epoch once per
// process, and every failed attempt.
func TestActivationCounterOnce(t *testing.T) {
	m := NewAgentMetrics(prometheus.NewRegistry())
	d := &DeploymentAgent{Metrics: m}
	for range 3 {
		d.count("uid", 1, OutcomeRefused, 0)
		d.count("uid", 1, OutcomeError, 0)
	}
	d.count("uid", 2, OutcomeRefused, 0)
	if got := activations(m, OutcomeRefused); got != 2 {
		t.Errorf("refused = %v, want one per epoch", got)
	}
	if got := activations(m, OutcomeError); got != 3 {
		t.Errorf("error = %v, want one per attempt", got)
	}
}

// TestBootRecord round-trips the record init writes, and exports only the
// latest source.
func TestBootRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-boot.json")
	if _, err := ReadBootRecord(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadBootRecord of nothing = %v, want os.ErrNotExist", err)
	}
	want := BootRecord{Source: BootCheckpointOffline, Reason: "restoring committed edge-a-1"}
	if err := WriteBootRecord(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBootRecord(path)
	if err != nil || got != want {
		t.Fatalf("ReadBootRecord = %+v, %v; want %+v", got, err, want)
	}

	// A later init clears it before installing, so a record it then fails
	// to write leaves none rather than this one.
	if err := ClearBootRecord(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootRecord(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ReadBootRecord after ClearBootRecord = %v, want os.ErrNotExist", err)
	}
	if err := ClearBootRecord(path); err != nil {
		t.Errorf("ClearBootRecord of nothing = %v", err)
	}

	m := NewAgentMetrics(prometheus.NewRegistry())
	m.SetBoot(BootConfigMap)
	m.SetBoot(got.Source)
	if n := testutil.CollectAndCount(m.boot); n != 1 {
		t.Errorf("boot source has %d series, want only the latest", n)
	}
	if v := testutil.ToFloat64(m.boot.WithLabelValues(string(BootCheckpointOffline))); v != 1 {
		t.Errorf("boot_source{source=%q} = %v, want 1", BootCheckpointOffline, v)
	}
}
