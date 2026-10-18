// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func gather(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, f := range families {
		out[f.GetName()] = f
	}
	return out
}

// sample is the value of name's series whose labels include every pair in
// labels, or -1 when there is none.
func sample(t *testing.T, reg *prometheus.Registry, name string, labels ...string) float64 {
	t.Helper()
	f, ok := gather(t, reg)[name]
	if !ok {
		return -1
	}
metrics:
	for _, m := range f.GetMetric() {
		got := map[string]string{}
		for _, l := range m.GetLabel() {
			got[l.GetName()] = l.GetValue()
		}
		for i := 0; i+1 < len(labels); i += 2 {
			if got[labels[i]] != labels[i+1] {
				continue metrics
			}
		}
		switch {
		case m.GetGauge() != nil:
			return m.GetGauge().GetValue()
		case m.GetCounter() != nil:
			return m.GetCounter().GetValue()
		case m.GetHistogram() != nil:
			return float64(m.GetHistogram().GetSampleCount())
		}
	}
	return -1
}

// attempts is startup_attempts_total for stage and result.
func attempts(t *testing.T, reg *prometheus.Registry, stage, result string) float64 {
	t.Helper()
	return sample(t, reg, "galactic_ingress_sidecar_startup_attempts_total", "stage", stage, "result", result)
}

func newLifecycleRegistry(t *testing.T) (*LifecycleMetrics, *prometheus.Registry) {
	t.Helper()
	m := NewLifecycleMetrics(5*time.Second, 30*time.Second)
	reg := prometheus.NewPedanticRegistry()
	m.MustRegister(reg)
	return m, reg
}

// stageIs asserts stage reports want and no other status.
func stageIs(t *testing.T, reg *prometheus.Registry, stage, want string) {
	t.Helper()
	for _, status := range stageStatuses {
		v := sample(t, reg, "galactic_ingress_sidecar_startup_stage_status", "stage", stage, "status", status)
		if (status == want) != (v == 1) || (v != 0 && v != 1) {
			t.Errorf("startup_stage_status{stage=%q,status=%q} = %v, want stage %s", stage, status, v, want)
		}
	}
}

func TestLifecycleMetricsInitialState(t *testing.T) {
	_, reg := newLifecycleRegistry(t)
	families := gather(t, reg)
	want := map[string]dto.MetricType{
		"galactic_ingress_sidecar_startup_stage_status":                   dto.MetricType_GAUGE,
		"galactic_ingress_sidecar_startup_attempts_total":                 dto.MetricType_COUNTER,
		"galactic_ingress_sidecar_startup_complete":                       dto.MetricType_GAUGE,
		"galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds": dto.MetricType_GAUGE,
		"galactic_ingress_sidecar_sweep_duration_seconds":                 dto.MetricType_HISTOGRAM,
		"galactic_ingress_sidecar_sweep_interval_seconds":                 dto.MetricType_GAUGE,
		"galactic_ingress_sidecar_teardown_grace_seconds":                 dto.MetricType_GAUGE,
		"galactic_ingress_sidecar_pruned_rows_total":                      dto.MetricType_COUNTER,
	}
	for name, typ := range want {
		f, ok := families[name]
		if !ok {
			t.Errorf("%s is not exported", name)
			continue
		}
		if f.GetType() != typ {
			t.Errorf("%s is a %v, want %v", name, f.GetType(), typ)
		}
		if strings.TrimSpace(f.GetHelp()) == "" {
			t.Errorf("%s has no HELP", name)
		}
	}
	if len(families) != len(want) {
		t.Errorf("exported %d families, want %d", len(families), len(want))
	}

	for _, stage := range startupStages {
		stageIs(t, reg, stage, StatusPending)
		for _, result := range attemptResults {
			if v := attempts(t, reg, stage, result); v != 0 {
				t.Errorf("startup_attempts_total{stage=%q,result=%q} = %v, want 0", stage, result, v)
			}
		}
	}
	for name, want := range map[string]float64{
		"galactic_ingress_sidecar_startup_complete":                       0,
		"galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds": 0,
		"galactic_ingress_sidecar_sweep_interval_seconds":                 5,
		"galactic_ingress_sidecar_teardown_grace_seconds":                 30,
		"galactic_ingress_sidecar_pruned_rows_total":                      0,
	} {
		if v := sample(t, reg, name); v != want {
			t.Errorf("%s = %v, want %v", name, v, want)
		}
	}
	// 3 stages x 5 statuses, 3 x 2 attempts, 5 scalars, and the histogram.
	if n := testutil.CollectAndCount(reg); n != 15+6+5+1 {
		t.Errorf("%d series, want %d", n, 15+6+5+1)
	}
}

func TestLifecycleMetricsNilIsInert(t *testing.T) {
	var m *LifecycleMetrics
	m.setStage(StageSeed, StatusRunning)
	m.attempt(StageSeed, errTest)
	m.pruned(3)
	m.startupComplete()
	m.sweepDone(m.sweepStart())
}

// runStartup runs RunStartup in the background until the test ends.
func runStartup(t *testing.T, c client.Reader, store *Store, m *LifecycleMetrics) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunStartup(ctx, c, store, time.Hour, m)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// TestRunStartupReportsSeedRetries: a failing EndpointSlice list leaves the
// seed failed, counts each failure, and holds inventory and prune pending;
// once the list succeeds every stage completes and startup is complete.
func TestRunStartupReportsSeedRetries(t *testing.T) {
	seedRetryInitial, seedRetryMax = time.Millisecond, time.Millisecond
	t.Cleanup(func() { seedRetryInitial, seedRetryMax = time.Second, 30*time.Second })

	var failing atomic.Bool
	failing.Store(true)
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if failing.Load() {
				return errTest
			}
			return c.List(ctx, list, opts...)
		},
	}).Build()
	backend := newFakeBackend()
	backend.pruneRemoved = 2
	m, reg := newLifecycleRegistry(t)
	runStartup(t, c, NewStore(backend, time.Hour, nil), m)

	waitFor(t, "two failed seed attempts", func() bool {
		return attempts(t, reg, StageSeed, ResultError) >= 2
	})
	if v := sample(t, reg, "galactic_ingress_sidecar_startup_complete"); v != 0 {
		t.Errorf("startup_complete = %v while the seed fails", v)
	}
	stageIs(t, reg, StageInventory, StatusPending)
	stageIs(t, reg, StagePrune, StatusPending)

	failing.Store(false)
	waitFor(t, "startup complete", func() bool {
		return sample(t, reg, "galactic_ingress_sidecar_startup_complete") == 1
	})
	for _, stage := range startupStages {
		stageIs(t, reg, stage, StatusComplete)
		if v := attempts(t, reg, stage, ResultSuccess); v != 1 {
			t.Errorf("startup_attempts_total{stage=%q,result=success} = %v, want 1", stage, v)
		}
	}
	if v := sample(t, reg, "galactic_ingress_sidecar_pruned_rows_total"); v != 2 {
		t.Errorf("pruned_rows_total = %v, want 2", v)
	}
}

// TestRunStartupReportsInventoryFailure: a failed inventory is reported, the
// prune is skipped rather than pending, and the sweep still starts.
func TestRunStartupReportsInventoryFailure(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	backend := newFakeBackend()
	backend.failListVRFs = errTest
	m, reg := newLifecycleRegistry(t)
	runStartup(t, c, NewStore(backend, time.Hour, nil), m)

	waitFor(t, "startup complete", func() bool {
		return sample(t, reg, "galactic_ingress_sidecar_startup_complete") == 1
	})
	stageIs(t, reg, StageSeed, StatusComplete)
	stageIs(t, reg, StageInventory, StatusFailed)
	stageIs(t, reg, StagePrune, StatusSkipped)
	if v := attempts(t, reg, StageInventory, ResultError); v != 1 {
		t.Errorf("inventory errors = %v, want 1", v)
	}
	if v := attempts(t, reg, StagePrune, ResultSuccess) + attempts(t, reg, StagePrune, ResultError); v != 0 {
		t.Errorf("prune attempts = %v after a failed inventory, want 0", v)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.pruned) != 0 {
		t.Error("the prune ran after a failed inventory")
	}
}

// TestRunStartupCountsPartialPrune: rows a failing prune removed before it
// failed are still counted, and the prune reports failed.
func TestRunStartupCountsPartialPrune(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	backend := newFakeBackend()
	backend.failPrune = errTest
	backend.pruneRemoved = 3
	m, reg := newLifecycleRegistry(t)
	runStartup(t, c, NewStore(backend, time.Hour, nil), m)

	waitFor(t, "startup complete", func() bool {
		return sample(t, reg, "galactic_ingress_sidecar_startup_complete") == 1
	})
	stageIs(t, reg, StagePrune, StatusFailed)
	if v := sample(t, reg, "galactic_ingress_sidecar_pruned_rows_total"); v != 3 {
		t.Errorf("pruned_rows_total = %v, want 3", v)
	}
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestSweepHeartbeat: each completed sweep, including one whose operations
// fail, moves the last-completed timestamp and observes its duration.
func TestSweepHeartbeat(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	m, reg := newLifecycleRegistry(t)
	m.now = clock.now

	backend := newFakeBackend()
	backend.failRemoveVRF = errTest
	backend.seedRoute("orphan", 9, mustPrefix(t, "fd00::9"), net.ParseIP("fd00:99::9"))
	store := NewStore(backend, 0, nil)
	if err := store.Inventory(context.Background(), time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}

	start := m.sweepStart()
	clock.advance(250 * time.Millisecond)
	store.Sweep(context.Background(), time.Now())
	m.sweepDone(start)

	if v := sample(t, reg, "galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds"); v != 1_700_000_000.25 {
		t.Errorf("sweep_last_completed_timestamp_seconds = %v, want 1700000000.25", v)
	}
	if v := sample(t, reg, "galactic_ingress_sidecar_sweep_duration_seconds"); v != 1 {
		t.Errorf("sweep_duration_seconds has %v observations, want 1", v)
	}
	help := gather(t, reg)["galactic_ingress_sidecar_sweep_duration_seconds"].GetHelp()
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP galactic_ingress_sidecar_sweep_duration_seconds `+help+`
# TYPE galactic_ingress_sidecar_sweep_duration_seconds histogram
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="0.001"} 0
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="0.005"} 0
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="0.01"} 0
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="0.05"} 0
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="0.1"} 0
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="0.25"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="0.5"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="1"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="2.5"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="5"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="10"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="30"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="60"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="120"} 1
galactic_ingress_sidecar_sweep_duration_seconds_bucket{le="+Inf"} 1
galactic_ingress_sidecar_sweep_duration_seconds_sum 0.25
galactic_ingress_sidecar_sweep_duration_seconds_count 1
`), "galactic_ingress_sidecar_sweep_duration_seconds"); err != nil {
		t.Error(err)
	}
}

// TestRunSweeperRecordsEverySweep: the real sweep loop records sweeps.
func TestRunSweeperRecordsEverySweep(t *testing.T) {
	m, reg := newLifecycleRegistry(t)
	store := NewStore(newFakeBackend(), time.Hour, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunSweeper(ctx, store, time.Millisecond, m)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor(t, "three sweeps", func() bool {
		return sample(t, reg, "galactic_ingress_sidecar_sweep_duration_seconds") >= 3
	})
	if v := sample(t, reg, "galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds"); v <= 0 {
		t.Errorf("sweep_last_completed_timestamp_seconds = %v after sweeps", v)
	}
}

// TestScrapeDuringBlockedSweep: a sweep blocked on the store's lock neither
// moves the heartbeat nor blocks a scrape, which is what makes a stalled sweep
// visible as a stale timestamp; once it runs, its duration includes the wait.
// Lifecycle instruments hold no reference to the store, so a scrape cannot
// take its lock; this checks the whole sidecar registry, legacy metrics
// included.
func TestScrapeDuringBlockedSweep(t *testing.T) {
	m, reg := newLifecycleRegistry(t)
	legacy := NewMetrics()
	legacy.MustRegister(reg)
	store := NewStore(newFakeBackend(), time.Hour, legacy)

	const blocked = 100 * time.Millisecond
	store.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunSweeper(ctx, store, time.Millisecond, m)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	time.Sleep(blocked)
	scraped := make(chan struct{})
	go func() {
		defer close(scraped)
		_, _ = reg.Gather()
	}()
	select {
	case <-scraped:
	case <-time.After(2 * time.Second):
		t.Fatal("a scrape blocked behind the store's lock")
	}
	if v := sample(t, reg, "galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds"); v != 0 {
		t.Errorf("sweep_last_completed_timestamp_seconds = %v while every sweep is blocked", v)
	}

	store.mu.Unlock()
	waitFor(t, "the blocked sweep", func() bool {
		return sample(t, reg, "galactic_ingress_sidecar_sweep_duration_seconds") >= 1
	})
	families := gather(t, reg)
	sum := families["galactic_ingress_sidecar_sweep_duration_seconds"].GetMetric()[0].GetHistogram().GetSampleSum()
	if sum < (blocked - 10*time.Millisecond).Seconds() {
		t.Errorf("sweep durations sum to %vs, want the %v the first sweep waited on the lock", sum, blocked)
	}
}

// TestShutdownDuringSeedRecordsNothing: an EndpointSlice list cut short by
// shutdown is not a failed attempt, and startup is not reported complete.
func TestShutdownDuringSeedRecordsNothing(t *testing.T) {
	listing := make(chan struct{})
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
			close(listing)
			<-ctx.Done()
			return ctx.Err()
		},
	}).Build()
	m, reg := newLifecycleRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunStartup(ctx, c, NewStore(newFakeBackend(), time.Hour, nil), time.Hour, m)
	}()
	<-listing
	cancel()
	<-done

	if v := attempts(t, reg, StageSeed, ResultError); v != 0 {
		t.Errorf("startup_attempts_total{stage=seed,result=error} = %v after a shutdown, want 0", v)
	}
	if v := sample(t, reg, "galactic_ingress_sidecar_startup_complete"); v != 0 {
		t.Errorf("startup_complete = %v after a shutdown during the seed", v)
	}
	stageIs(t, reg, StageInventory, StatusPending)
}
