// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

const (
	mChecks       = "galactic_ingress_sidecar_datapath_checks_total"
	mCheckStatus  = "galactic_ingress_sidecar_datapath_check_status"
	mCheckLast    = "galactic_ingress_sidecar_datapath_check_last_completed_timestamp_seconds"
	mDPReapplies  = "galactic_ingress_sidecar_datapath_reapply_total"
	mReapplyPend  = "galactic_ingress_sidecar_datapath_reapply_pending"
	testCheckTime = 1_700_000_000
)

type datapathStore struct {
	*Store
	backend *fakeBackend
	reg     *prometheus.Registry
	metrics *DatapathMetrics
}

func newDatapathStore(t *testing.T) *datapathStore {
	t.Helper()
	m := NewDatapathMetrics()
	m.now = func() time.Time { return time.Unix(testCheckTime, 0) }
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(m.collectors()...)
	backend := newFakeBackend()
	backend.generation = testGenLoaded
	store := NewStore(backend, time.Hour, nil)
	store.SetDatapathMetrics(m)
	return &datapathStore{Store: store, backend: backend, reg: reg, metrics: m}
}

func (d *datapathStore) value(t *testing.T, name string, labels ...string) float64 {
	t.Helper()
	families, err := d.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	series:
		for _, m := range f.GetMetric() {
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			for i := 0; i+1 < len(labels); i += 2 {
				if got[labels[i]] != labels[i+1] {
					continue series
				}
			}
			return m.GetGauge().GetValue() + m.GetCounter().GetValue()
		}
	}
	return -1
}

// status asserts check reports want and no other status.
func (d *datapathStore) status(t *testing.T, check, want string) {
	t.Helper()
	for _, s := range checkStatuses {
		v := d.value(t, mCheckStatus, "check", check, "status", s)
		if (s == want) != (v == 1) {
			t.Errorf("datapath_check_status{check=%q,status=%q} = %v, want status %s", check, s, v, want)
		}
	}
}

func (d *datapathStore) install(t *testing.T) {
	t.Helper()
	if err := d.SetDesired(context.Background(), "ns/a", &DesiredRoute{
		VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1"),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDatapathMetricsInitialState(t *testing.T) {
	d := newDatapathStore(t)
	families, err := d.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]dto.MetricType{
		mChecks: dto.MetricType_COUNTER, mCheckStatus: dto.MetricType_GAUGE, mCheckLast: dto.MetricType_GAUGE,
		mDPReapplies: dto.MetricType_COUNTER, mReapplyPend: dto.MetricType_GAUGE,
	}
	if len(families) != len(want) {
		t.Errorf("exported %d families, want %d", len(families), len(want))
	}
	for _, f := range families {
		if f.GetType() != want[f.GetName()] || strings.TrimSpace(f.GetHelp()) == "" {
			t.Errorf("%s: type %v, help %q", f.GetName(), f.GetType(), f.GetHelp())
		}
	}
	for _, check := range datapathChecks {
		d.status(t, check, CheckUnknown)
		if v := d.value(t, mCheckLast, "check", check); v != 0 {
			t.Errorf("%s last completed = %v before any check", check, v)
		}
	}
	series := 0
	for _, check := range datapathChecks {
		series += len(checkResults[check]) + len(checkStatuses) + 1 // results, statuses, timestamp
	}
	series += len(reapplyReasons)*len(reapplyResults) + 1 // reapplies, pending
	if n := testutil.CollectAndCount(d.reg); n != series {
		t.Errorf("%d series, want %d", n, series)
	}
}

// TestDatapathChecksReportEachOutcome: each check reports ok, missing or
// error as it actually completed, never a stale ok after a failed read, and
// the timestamp moves with every completion.
func TestDatapathChecksReportEachOutcome(t *testing.T) {
	d := newDatapathStore(t)
	ctx := context.Background()
	d.install(t)

	d.Sweep(ctx, time.Now())
	d.status(t, CheckGeneration, CheckOK)
	d.status(t, CheckRegistrationRows, CheckOK)
	if v := d.value(t, mCheckLast, "check", CheckRegistrationRows); v != testCheckTime {
		t.Errorf("registration_rows last completed = %v, want %v", v, testCheckTime)
	}

	d.backend.failRowsRead = errTest
	d.Sweep(ctx, time.Now())
	d.status(t, CheckRegistrationRows, CheckError)
	if v := d.value(t, mDPReapplies, "reason", ReapplyRowsMissing, "result", "success"); v != 0 {
		t.Errorf("a failed row read triggered a reapply (%v); it must stay conservative", v)
	}

	d.backend.failGeneration = errTest
	d.Sweep(ctx, time.Now())
	d.status(t, CheckGeneration, CheckError)
	if v := d.value(t, mChecks, "check", CheckGeneration, "result", CheckError); v != 1 {
		t.Errorf("generation errors = %v, want 1", v)
	}
}

// TestReapplyReasons: rows going missing, a reload, and the retry of a
// failed pass each count under their own reason, and the pending gauge
// follows the last pass.
func TestReapplyReasons(t *testing.T) {
	d := newDatapathStore(t)
	ctx := context.Background()
	d.install(t)

	d.backend.rowsMissing = map[uint32]bool{d.backend.vrfs[testVPC1]: true}
	d.Sweep(ctx, time.Now())
	d.status(t, CheckRegistrationRows, CheckMissing)
	if v := d.value(t, mDPReapplies, "reason", ReapplyRowsMissing, "result", "success"); v != 1 {
		t.Errorf("rows_missing reapplies = %v, want 1", v)
	}
	d.backend.rowsMissing = nil

	d.backend.reloadDatapath()
	d.backend.failEnsureRoute = errTest
	d.Sweep(ctx, time.Now())
	if v := d.value(t, mDPReapplies, "reason", ReapplyGenerationChanged, "result", "error"); v != 1 {
		t.Errorf("failed generation_changed reapplies = %v, want 1", v)
	}
	if v := d.value(t, mReapplyPend); v != 1 {
		t.Errorf("datapath_reapply_pending = %v after a failed pass, want 1", v)
	}

	d.backend.failEnsureRoute = nil
	d.Sweep(ctx, time.Now())
	if v := d.value(t, mDPReapplies, "reason", ReapplyRetry, "result", "success"); v != 1 {
		t.Errorf("retry reapplies = %v, want 1", v)
	}
	if v := d.value(t, mReapplyPend); v != 0 {
		t.Errorf("datapath_reapply_pending = %v after a successful retry, want 0", v)
	}
}

// TestGenerationChangeOutranksRetry: a reload during a pending retry is
// counted as generation_changed.
func TestGenerationChangeOutranksRetry(t *testing.T) {
	d := newDatapathStore(t)
	ctx := context.Background()
	d.install(t)

	d.backend.reloadDatapath()
	d.backend.failEnsureRoute = errTest
	d.Sweep(ctx, time.Now()) // fails, so a retry is pending

	d.backend.mu.Lock()
	d.backend.generation = "3/3"
	d.backend.failEnsureRoute = nil
	d.backend.mu.Unlock()
	d.Sweep(ctx, time.Now())
	if v := d.value(t, mDPReapplies, "reason", ReapplyGenerationChanged, "result", "success"); v != 1 {
		t.Errorf("generation_changed successes = %v, want 1", v)
	}
	if v := d.value(t, mDPReapplies, "reason", ReapplyRetry, "result", "success"); v != 0 {
		t.Errorf("retry successes = %v, want 0: the reload outranks the retry", v)
	}
}

func TestDatapathMetricsNilIsInert(t *testing.T) {
	var m *DatapathMetrics
	m.checked(CheckGeneration, CheckOK)
	m.reapplied(ReapplyRetry, false)
}

// TestRowStatusNeverStaysStaleOK: an ok row check that could not be re-read
// becomes unknown, while a missing one stays visible until a read replaces
// it; a sweep with nothing to read back records nothing.
func TestRowStatusNeverStaysStaleOK(t *testing.T) {
	d := newDatapathStore(t)
	ctx := context.Background()

	d.Sweep(ctx, time.Now()) // no VRFs: nothing to read back
	d.status(t, CheckRegistrationRows, CheckUnknown)
	if v := d.value(t, mChecks, "check", CheckRegistrationRows, "result", CheckOK); v != 0 {
		t.Errorf("a sweep with no rows to read recorded %v ok checks", v)
	}

	d.install(t)
	d.Sweep(ctx, time.Now())
	d.status(t, CheckRegistrationRows, CheckOK)

	d.backend.failGeneration = errTest
	d.Sweep(ctx, time.Now())
	d.status(t, CheckRegistrationRows, CheckUnknown)
	d.backend.failGeneration = nil

	// Rows go missing and every reapply fails: missing stays visible.
	d.Sweep(ctx, time.Now())
	d.backend.rowsMissing = map[uint32]bool{d.backend.vrfs[testVPC1]: true}
	d.backend.failEnsureRoute = errTest
	d.Sweep(ctx, time.Now())
	d.Sweep(ctx, time.Now())
	d.status(t, CheckRegistrationRows, CheckMissing)
	if v := d.value(t, mReapplyPend); v != 1 {
		t.Errorf("datapath_reapply_pending = %v while every reapply fails", v)
	}
}

// TestFailedRowReadDoesNotRepair: a failed read is an error, and repair
// stays as conservative as before: nothing is reapplied.
func TestFailedRowReadDoesNotRepair(t *testing.T) {
	d := newDatapathStore(t)
	ctx := context.Background()
	d.install(t)
	d.backend.failRowsRead = errTest
	before := len(d.backend.calls)
	d.Sweep(ctx, time.Now())
	for _, call := range d.backend.callsSince(before) {
		if strings.HasPrefix(call, "EnsureVRF") || strings.HasPrefix(call, "EnsureRoute") {
			t.Errorf("a failed row read caused %s", call)
		}
	}
	for _, reason := range reapplyReasons {
		for _, result := range reapplyResults {
			if v := d.value(t, mDPReapplies, "reason", reason, "result", result); v != 0 {
				t.Errorf("reapply_total{reason=%q,result=%q} = %v after a failed read", reason, result, v)
			}
		}
	}
}

// TestReloadReappliesOnce: a reload with nothing pending reapplies once as
// generation_changed and leaves nothing pending.
func TestReloadReappliesOnce(t *testing.T) {
	d := newDatapathStore(t)
	ctx := context.Background()
	d.install(t)
	d.backend.reloadDatapath()
	d.Sweep(ctx, time.Now())
	if v := d.value(t, mDPReapplies, "reason", ReapplyGenerationChanged, "result", "success"); v != 1 {
		t.Errorf("generation_changed successes = %v, want 1", v)
	}
	if v := d.value(t, mReapplyPend); v != 0 {
		t.Errorf("datapath_reapply_pending = %v after a successful pass", v)
	}
}

// TestSweepWithoutDatapathMetrics: a Store without datapath metrics sweeps
// as before.
func TestSweepWithoutDatapathMetrics(t *testing.T) {
	backend := newFakeBackend()
	backend.generation = testGenLoaded
	store := NewStore(backend, time.Hour, nil)
	if err := store.SetDesired(context.Background(), "ns/a", &DesiredRoute{
		VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1"),
	}); err != nil {
		t.Fatal(err)
	}
	backend.reloadDatapath()
	store.Sweep(context.Background(), time.Now())
	if backend.routeCount() != 1 {
		t.Error("the reload was not repaired without datapath metrics")
	}
}
