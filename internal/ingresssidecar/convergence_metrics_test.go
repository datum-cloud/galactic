// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

const (
	mClaimsDesired = "galactic_ingress_sidecar_route_claims_desired"
	mClaimsPending = "galactic_ingress_sidecar_route_claims_apply_pending"
	mOldestPending = "galactic_ingress_sidecar_route_apply_oldest_pending_timestamp_seconds"
	mOverdue       = "galactic_ingress_sidecar_teardown_overdue"
	mOperations    = "galactic_ingress_sidecar_operations_total"
	mApplyDelay    = "galactic_ingress_sidecar_route_apply_delay_seconds"
)

// Slice UIDs for a slice and the one recreated under its name.
const (
	testSliceUID1 = "uid-1"
	testSliceUID2 = "uid-2"
)

// stepClock is a clock tests move by hand.
type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stepClock) step(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// convergenceStore is a Store reporting to its own registry, on a clock
// starting at t0.
type convergenceStore struct {
	*Store
	backend *fakeBackend
	reg     *prometheus.Registry
	clock   *stepClock
	legacy  *Metrics
}

var t0 = time.Unix(1_700_000_000, 0)

func newConvergenceStore(t *testing.T, grace time.Duration) *convergenceStore {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	m := NewConvergenceMetrics()
	reg.MustRegister(m.collectors()...)
	legacy := NewMetrics()
	reg.MustRegister(legacy.collectors()...)
	backend := newFakeBackend()
	store := NewStore(backend, grace, legacy)
	clock := &stepClock{t: t0}
	store.clock = clock.now
	store.SetConvergenceMetrics(m)
	return &convergenceStore{Store: store, backend: backend, reg: reg, clock: clock, legacy: legacy}
}

// value is the value of name's series carrying every label pair given, or -1.
func (c *convergenceStore) value(t *testing.T, name string, labels ...string) float64 {
	t.Helper()
	families, err := c.reg.Gather()
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
			if m.GetGauge() != nil {
				return m.GetGauge().GetValue()
			}
			return m.GetCounter().GetValue()
		}
	}
	return -1
}

func (c *convergenceStore) claims(t *testing.T, desired, pending float64, oldest time.Time) {
	t.Helper()
	if v := c.value(t, mClaimsDesired); v != desired {
		t.Errorf("route_claims_desired = %v, want %v", v, desired)
	}
	if v := c.value(t, mClaimsPending); v != pending {
		t.Errorf("route_claims_apply_pending = %v, want %v", v, pending)
	}
	want := 0.0
	if !oldest.IsZero() {
		want = unixSecondsOf(oldest)
	}
	if v := c.value(t, mOldestPending); v != want {
		t.Errorf("route_apply_oldest_pending_timestamp_seconds = %v, want %v", v, want)
	}
}

func (c *convergenceStore) ops(t *testing.T, op, result string, want float64) {
	t.Helper()
	if v := c.value(t, mOperations, "operation", op, "result", result); v != want {
		t.Errorf("operations_total{operation=%q,result=%q} = %v, want %v", op, result, v, want)
	}
}

func route(t *testing.T, prefix, sid string) *DesiredRoute {
	t.Helper()
	return &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, prefix), SID: net.ParseIP(sid)}
}

func TestConvergenceMetricsInitialState(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(NewConvergenceMetrics().collectors()...)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]dto.MetricType{
		mClaimsDesired: dto.MetricType_GAUGE,
		mClaimsPending: dto.MetricType_GAUGE,
		mOldestPending: dto.MetricType_GAUGE,
		mOverdue:       dto.MetricType_GAUGE,
		mOperations:    dto.MetricType_COUNTER,
		mApplyDelay:    dto.MetricType_HISTOGRAM,
	}
	if len(families) != len(types) {
		t.Errorf("exported %d families, want %d", len(families), len(types))
	}
	for _, f := range families {
		if want, ok := types[f.GetName()]; !ok || f.GetType() != want || strings.TrimSpace(f.GetHelp()) == "" {
			t.Errorf("%s: type %v, help %q; want type %v and a help", f.GetName(), f.GetType(), f.GetHelp(), want)
		}
		for _, m := range f.GetMetric() {
			if v := m.GetGauge().GetValue() + m.GetCounter().GetValue() +
				float64(m.GetHistogram().GetSampleCount()); v != 0 {
				t.Errorf("%s%v = %v at start, want 0", f.GetName(), m.GetLabel(), v)
			}
		}
	}
	// 3 scalars, 2 teardown resources, 6 operations x 2 results, 1 histogram.
	if n := testutil.CollectAndCount(reg); n != 3+2+12+1 {
		t.Errorf("%d series, want %d", n, 3+2+12+1)
	}
}

// applyDelays is the apply-delay histogram's sample count and sum.
func (c *convergenceStore) applyDelays(t *testing.T) (uint64, float64) {
	t.Helper()
	families, err := c.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == mApplyDelay {
			h := f.GetMetric()[0].GetHistogram()
			return h.GetSampleCount(), h.GetSampleSum()
		}
	}
	t.Fatalf("%s not exported", mApplyDelay)
	return 0, 0
}

// TestApplyDelaySpansRetries: the apply delay runs from the moment a
// claim first became pending through failed attempts to the apply that
// succeeds, so a route stuck behind sweep retries shows its whole wait. Only
// a new, reactivated or changed claim is timed, not a reconcile that changes
// nothing. A claim withdrawn while pending is not counted as applied.
func TestApplyDelaySpansRetries(t *testing.T) {
	c := newConvergenceStore(t, time.Hour)
	ctx := context.Background()

	// Applied at once: one sample of zero.
	if err := c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::1")); err != nil {
		t.Fatal(err)
	}
	if n, sum := c.applyDelays(t); n != 1 || sum != 0 {
		t.Fatalf("after a prompt apply: %d samples summing %v, want 1 summing 0", n, sum)
	}

	// Reconciles that change nothing, as resyncs and the watch's initial list
	// after the seed are, are not timed; a changed route is.
	for range 3 {
		if err := c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::1")); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := c.applyDelays(t); n != 1 {
		t.Fatalf("unchanged reconciles were timed: %d samples, want 1", n)
	}
	if err := c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::9")); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.applyDelays(t); n != 2 {
		t.Fatalf("a changed route was not timed: %d samples, want 2", n)
	}

	// Fails, retried by two sweeps a minute apart, then applies.
	c.backend.mu.Lock()
	c.backend.failEnsureRoute = errTest
	c.backend.mu.Unlock()
	_ = c.SetDesired(ctx, "ns/b", route(t, "fd00::2", "fd00:99::1"))
	c.clock.step(time.Minute)
	c.Sweep(ctx, c.clock.now())
	if n, _ := c.applyDelays(t); n != 2 {
		t.Fatalf("a failed retry was counted: %d samples, want 2", n)
	}
	c.backend.mu.Lock()
	c.backend.failEnsureRoute = nil
	c.backend.mu.Unlock()
	c.clock.step(time.Minute)
	c.Sweep(ctx, c.clock.now())
	if n, sum := c.applyDelays(t); n != 3 || sum != 120 {
		t.Fatalf("after the retried apply: %d samples summing %v, want 3 summing 120", n, sum)
	}

	// Pending, then withdrawn before it applies: no sample.
	c.backend.mu.Lock()
	c.backend.failEnsureRoute = errTest
	c.backend.mu.Unlock()
	_ = c.SetDesired(ctx, "ns/c", route(t, "fd00::3", "fd00:99::1"))
	c.clock.step(time.Minute)
	if err := c.SetDesired(ctx, "ns/c", nil); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.applyDelays(t); n != 3 {
		t.Errorf("a withdrawn claim was counted as applied: %d samples, want 3", n)
	}
}

// TestFirstInstallLog: a route's first install logs, at debug level,
// its slice, when the slice was created and first observed, and both delays.
// A later update of the same slice does not log again. A slice recreated
// under the same name, as a replaced pod's is, logs as new even when its
// predecessor's route never left the store.
func TestFirstInstallLog(t *testing.T) {
	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&syncWriter{w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	c := newConvergenceStore(t, time.Hour)
	ctx := context.Background()
	c.backend.mu.Lock()
	c.backend.failEnsureRoute = errTest
	c.backend.mu.Unlock()
	r := route(t, "fd00::1", "fd00:99::1")
	r.SliceCreated = t0.Add(-45 * time.Second)
	r.SliceUID = testSliceUID1
	_ = c.SetDesired(ctx, "ns/a", r)
	c.clock.step(30 * time.Second)
	c.backend.mu.Lock()
	c.backend.failEnsureRoute = nil
	c.backend.mu.Unlock()
	c.Sweep(ctx, c.clock.now())
	update := route(t, "fd00::1", "fd00:99::2")
	update.SliceUID = testSliceUID1
	_ = c.SetDesired(ctx, "ns/a", update)

	out := buf.String()
	if n := strings.Count(out, "applied route for new EndpointSlice"); n != 1 {
		t.Fatalf("logged %d first installs, want 1:\n%s", n, out)
	}
	for _, want := range []string{
		"endpointslice=ns/a", "vpc=" + testVPC1, "prefix=fd00::1/128",
		"sinceObserved=30s", "sinceCreated=1m15s", "sliceCreated=", "observed=", "installed=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("first-install log lacks %q:\n%s", want, out)
		}
	}

	// The pod is replaced: same slice name, new UID, no reconcile in between
	// that saw the old slice gone.
	c.clock.step(time.Minute)
	replaced := route(t, "fd00::1", "fd00:99::2")
	replaced.SliceUID = testSliceUID2
	replaced.SliceCreated = c.clock.now().Add(-10 * time.Second)
	if err := c.SetDesired(ctx, "ns/a", replaced); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	if n := strings.Count(out, "applied route for new EndpointSlice"); n != 2 {
		t.Fatalf("logged %d first installs after a replacement, want 2:\n%s", n, out)
	}
	if !strings.Contains(out, "sinceObserved=0s sliceCreated=") || !strings.Contains(out, "sinceCreated=10s") {
		t.Errorf("replacement not timed from its own observation and creation:\n%s", out)
	}
}

// syncWriter serializes writes to w.
type syncWriter struct {
	mu sync.Mutex
	w  *strings.Builder
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// TestPendingAgeSurvivesRetries: a claim that cannot be applied stays pending
// from the moment it first failed, through failed retries and a newer update,
// and clears when it finally applies.
func TestPendingAgeSurvivesRetries(t *testing.T) {
	c := newConvergenceStore(t, time.Hour)
	ctx := context.Background()
	c.backend.failEnsureRoute = errTest

	if err := c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::1")); err == nil {
		t.Fatal("SetDesired succeeded against a failing backend")
	}
	c.claims(t, 1, 1, t0)
	c.ops(t, OpEnsureVRF, OpSuccess, 1)
	c.ops(t, OpEnsureRoute, OpError, 1)

	c.clock.step(time.Minute)
	c.Sweep(ctx, c.clock.now())
	c.claims(t, 1, 1, t0)

	c.clock.step(time.Minute)
	_ = c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::2"))
	c.claims(t, 1, 1, t0)
	c.ops(t, OpEnsureRoute, OpError, 3)

	c.backend.mu.Lock()
	c.backend.failEnsureRoute = nil
	c.backend.mu.Unlock()
	c.Sweep(ctx, c.clock.now())
	c.claims(t, 1, 0, time.Time{})
	c.ops(t, OpEnsureRoute, OpSuccess, 1)
	opErrs := c.value(t, mOperations, "operation", OpEnsureRoute, "result", OpError)
	if legacy := c.legacyErrors(t, "ensure_route"); opErrs != legacy {
		t.Errorf("operations_total errors %v and reconcile_errors_total %v count different failures", opErrs, legacy)
	}
}

func (c *convergenceStore) legacyErrors(t *testing.T, kind string) float64 {
	t.Helper()
	return c.value(t, "galactic_ingress_sidecar_reconcile_errors_total", "kind", kind)
}

// TestInstalledRouteCanBePending: a failed update of an installed route is
// pending while route_active still counts it, so desired minus active cannot
// stand in for the apply backlog.
func TestInstalledRouteCanBePending(t *testing.T) {
	c := newConvergenceStore(t, time.Hour)
	ctx := context.Background()
	if err := c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::1")); err != nil {
		t.Fatal(err)
	}
	c.claims(t, 1, 0, time.Time{})

	c.backend.failEnsureRoute = errTest
	c.clock.step(time.Second)
	_ = c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::2"))
	c.claims(t, 1, 1, t0.Add(time.Second))
	if v := c.value(t, "galactic_ingress_sidecar_route_active"); v != 1 {
		t.Errorf("route_active = %v, want the still-installed route counted", v)
	}
}

// TestOldestPendingMovesToTheNext: when the oldest pending claim stops being
// desired, the oldest becomes the next one, and none once all are gone.
func TestOldestPendingMovesToTheNext(t *testing.T) {
	c := newConvergenceStore(t, time.Hour)
	ctx := context.Background()
	c.backend.failEnsureRoute = errTest
	_ = c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::1"))
	c.clock.step(10 * time.Second)
	_ = c.SetDesired(ctx, "ns/b", route(t, "fd00::2", "fd00:99::2"))
	c.claims(t, 2, 2, t0)

	if err := c.SetDesired(ctx, "ns/a", nil); err != nil {
		t.Fatal(err)
	}
	c.claims(t, 1, 1, t0.Add(10*time.Second))

	if err := c.SetDesired(ctx, "ns/b", nil); err != nil {
		t.Fatal(err)
	}
	c.claims(t, 0, 0, time.Time{})

	// Reactivated during its grace period, a claim is pending afresh.
	c.clock.step(time.Minute)
	_ = c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::1"))
	c.claims(t, 1, 1, t0.Add(70*time.Second))
}

// TestUpdateKeepsPendingAge: a newer update of a pending claim keeps the
// claim's own pending start, which the oldest takes over once an older claim
// clears and forces a rescan.
func TestUpdateKeepsPendingAge(t *testing.T) {
	c := newConvergenceStore(t, time.Hour)
	ctx := context.Background()
	c.backend.failEnsureRoute = errTest
	_ = c.SetDesired(ctx, "ns/older", route(t, "fd00::1", "fd00:99::1"))
	c.clock.step(time.Minute)
	_ = c.SetDesired(ctx, "ns/a", route(t, "fd00::2", "fd00:99::2"))
	c.clock.step(time.Minute)
	_ = c.SetDesired(ctx, "ns/a", route(t, "fd00::2", "fd00:99::3"))

	if err := c.SetDesired(ctx, "ns/older", nil); err != nil {
		t.Fatal(err)
	}
	c.claims(t, 1, 1, t0.Add(time.Minute))
}

// TestTeardownOverdue: removal inside the grace period is ordinary draining;
// once the grace has run out and removal fails, the route is overdue, and so
// is its VRF later. Both clear once removal succeeds.
func TestTeardownOverdue(t *testing.T) {
	c := newConvergenceStore(t, time.Minute)
	ctx := context.Background()
	if err := c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::1")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDesired(ctx, "ns/a", nil); err != nil {
		t.Fatal(err)
	}
	c.backend.failRemoveRoute = errTest
	c.backend.failRemoveVRF = errTest

	c.Sweep(ctx, time.Now().Add(30*time.Second))
	overdue := func(routes, vrfs float64) {
		t.Helper()
		if v := c.value(t, mOverdue, "resource", ResourceRoute); v != routes {
			t.Errorf("teardown_overdue{resource=route} = %v, want %v", v, routes)
		}
		if v := c.value(t, mOverdue, "resource", ResourceVRF); v != vrfs {
			t.Errorf("teardown_overdue{resource=vrf} = %v, want %v", v, vrfs)
		}
	}
	overdue(0, 0)

	c.Sweep(ctx, time.Now().Add(2*time.Minute))
	overdue(1, 0)
	c.ops(t, OpRemoveRoute, OpError, 1)

	c.backend.mu.Lock()
	c.backend.failRemoveRoute = nil
	c.backend.mu.Unlock()
	c.Sweep(ctx, time.Now().Add(3*time.Minute)) // route removed; the VRF's grace starts
	c.Sweep(ctx, time.Now().Add(5*time.Minute)) // the VRF's grace has run out
	overdue(0, 1)
	c.ops(t, OpRemoveVRF, OpError, 1)

	c.backend.mu.Lock()
	c.backend.failRemoveVRF = nil
	c.backend.mu.Unlock()
	c.Sweep(ctx, time.Now().Add(6*time.Minute))
	overdue(0, 0)
	c.ops(t, OpRemoveRoute, OpSuccess, 1)
	c.ops(t, OpRemoveVRF, OpSuccess, 1)
}

// TestSharedPrefixClaims: two slices claiming one prefix are two desired
// claims; dropping one never removes the kernel route the other needs, so
// no removal is recorded.
func TestSharedPrefixClaims(t *testing.T) {
	c := newConvergenceStore(t, 0)
	ctx := context.Background()
	for _, key := range []string{"ns/a", "ns/b"} {
		if err := c.SetDesired(ctx, key, route(t, "fd00::1", "fd00:99::1")); err != nil {
			t.Fatal(err)
		}
	}
	c.claims(t, 2, 0, time.Time{})
	if err := c.SetDesired(ctx, "ns/a", nil); err != nil {
		t.Fatal(err)
	}
	c.Sweep(ctx, time.Now().Add(time.Second))
	c.claims(t, 1, 0, time.Time{})
	c.ops(t, OpRemoveRoute, OpSuccess, 0)
	c.ops(t, OpRemoveRoute, OpError, 0)
	if n := c.backend.routeCount(); n != 1 {
		t.Errorf("%d kernel routes, want the shared one kept", n)
	}
}

// TestReapplyCountsOperations: a reapply after a datapath reload records its
// operations under their own names.
func TestReapplyCountsOperations(t *testing.T) {
	c := newConvergenceStore(t, time.Hour)
	ctx := context.Background()
	c.backend.generation = testGenLoaded
	if err := c.SetDesired(ctx, "ns/a", route(t, "fd00::1", "fd00:99::1")); err != nil {
		t.Fatal(err)
	}
	c.backend.reloadDatapath()
	c.Sweep(ctx, time.Now())
	c.ops(t, OpReapplyVRF, OpSuccess, 1)
	c.ops(t, OpReapplyRoute, OpSuccess, 1)
	c.ops(t, OpEnsureVRF, OpSuccess, 1)
	c.ops(t, OpEnsureRoute, OpSuccess, 1)
}

// TestConvergenceScrapeNeverTakesTheStoreLock: collection reads published
// values, so a store blocked mid-operation cannot block a scrape.
func TestConvergenceScrapeNeverTakesTheStoreLock(t *testing.T) {
	c := newConvergenceStore(t, time.Hour)
	c.mu.Lock()
	defer c.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.reg.Gather()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a scrape blocked on the store's lock")
	}
}

// TestSeedingIsLinear: applying many claims, with a pending backlog the whole
// time, never rescans every route per update.
func TestSeedingIsLinear(t *testing.T) {
	c := newConvergenceStore(t, time.Hour)
	ctx := context.Background()
	c.backend.failEnsureRoute = errTest
	const n = 5000
	start := time.Now()
	for i := range n {
		c.clock.step(time.Millisecond)
		_ = c.SetDesired(ctx, fmt.Sprintf("ns/s%d", i), route(t, fmt.Sprintf("fd00::%x", i+1), "fd00:99::1"))
	}
	elapsed := time.Since(start)
	c.claims(t, n, n, t0.Add(time.Millisecond))
	t.Logf("%d pending claims applied in %v", n, elapsed)
}

func BenchmarkSetDesiredWithBacklog(b *testing.B) {
	backend := newFakeBackend()
	backend.failEnsureRoute = errTest
	store := NewStore(backend, time.Hour, nil)
	store.SetConvergenceMetrics(NewConvergenceMetrics())
	ctx := context.Background()
	for i := range 10000 {
		_ = store.SetDesired(ctx, fmt.Sprintf("ns/seed%d", i), &DesiredRoute{
			VPC: testVPC1, Prefix: &net.IPNet{IP: net.ParseIP(fmt.Sprintf("fd00::%x", i+1)), Mask: net.CIDRMask(128, 128)},
			SID: net.ParseIP("fd00:99::1"),
		})
	}
	b.ResetTimer()
	for i := range b.N {
		_ = store.SetDesired(ctx, fmt.Sprintf("ns/b%d", i%100), &DesiredRoute{
			VPC: testVPC1, Prefix: &net.IPNet{IP: net.ParseIP(fmt.Sprintf("fd01::%x", i%100+1)), Mask: net.CIDRMask(128, 128)},
			SID: net.ParseIP("fd00:99::1"),
		})
	}
}

// recountLocked recomputes the claim counts and oldest pending start from
// every route. Callers must hold s.mu.
func (s *Store) recountLocked() (desired, pending int, oldest time.Time) {
	for _, r := range s.routes {
		d, p := r.claim()
		if d {
			desired++
		}
		if p {
			pending++
			if oldest.IsZero() || r.pendingSince.Before(oldest) {
				oldest = r.pendingSince
			}
		}
		if !p && !r.pendingSince.IsZero() {
			oldest = time.Unix(-1, 0) // a cleared claim kept its pending start: report as drift
		}
	}
	return desired, pending, oldest
}

// TestClaimBookkeepingMatchesARecount: under random interleavings of
// updates, removals, reactivation, failures, reloads, inventory and sweeps,
// the incrementally kept counts and oldest pending start always equal a
// recount from every route.
func TestClaimBookkeepingMatchesARecount(t *testing.T) {
	keys := []string{"ns/a", "ns/b", "ns/c", "ns/d"}
	prefixes := []string{"fd00::1", "fd00::2", "fd00::3"}
	for seed := range int64(40) {
		rng := rand.New(rand.NewSource(seed))
		c := newConvergenceStore(t, time.Minute)
		ctx := context.Background()
		now := time.Now()
		c.backend.generation = testGenLoaded
		for step := range 80 {
			c.clock.step(time.Duration(rng.Intn(5)) * time.Second)
			c.backend.mu.Lock()
			switch rng.Intn(10) {
			case 0:
				c.backend.failEnsureRoute = maybeErr(rng)
			case 1:
				c.backend.failEnsureVRF = maybeErr(rng)
			case 2:
				c.backend.failRemoveRoute = maybeErr(rng)
			}
			c.backend.mu.Unlock()
			switch rng.Intn(6) {
			case 0, 1:
				_ = c.SetDesired(ctx, keys[rng.Intn(len(keys))],
					route(t, prefixes[rng.Intn(len(prefixes))], fmt.Sprintf("fd00:99::%d", rng.Intn(3)+1)))
			case 2:
				_ = c.SetDesired(ctx, keys[rng.Intn(len(keys))], nil)
			case 3:
				now = now.Add(time.Duration(rng.Intn(90)) * time.Second)
				c.Sweep(ctx, now)
			case 4:
				c.backend.reloadDatapath()
			case 5:
				_ = c.Inventory(ctx, now)
			}
			c.mu.Lock()
			desired, pending, oldest := c.recountLocked()
			if desired != c.desiredClaims || pending != c.pendingClaims || !oldest.Equal(c.oldestPendingLocked()) {
				t.Fatalf("seed %d step %d: kept (%d, %d, %v), recount (%d, %d, %v)", seed, step,
					c.desiredClaims, c.pendingClaims, c.oldestPendingLocked(), desired, pending, oldest)
			}
			c.mu.Unlock()
		}
	}
}

func maybeErr(rng *rand.Rand) error {
	if rng.Intn(2) == 0 {
		return errTest
	}
	return nil
}

// BenchmarkDrainOldestFirst applies a large pending backlog in the order it
// became pending, each update clearing the oldest claim, the case that would
// make a rescan per update quadratic.
func BenchmarkDrainOldestFirst(b *testing.B) {
	for range b.N {
		b.StopTimer()
		backend := newFakeBackend()
		backend.failEnsureRoute = errTest
		store := NewStore(backend, time.Hour, nil)
		store.SetConvergenceMetrics(NewConvergenceMetrics())
		ctx := context.Background()
		const n = 10000
		routes := make([]*DesiredRoute, n)
		for i := range n {
			routes[i] = &DesiredRoute{
				VPC: testVPC1, Prefix: &net.IPNet{IP: net.ParseIP(fmt.Sprintf("fd00::%x", i+1)), Mask: net.CIDRMask(128, 128)},
				SID: net.ParseIP("fd00:99::1"),
			}
			_ = store.SetDesired(ctx, fmt.Sprintf("ns/s%d", i), routes[i])
		}
		backend.failEnsureRoute = nil
		b.StartTimer()
		for i := range n {
			_ = store.SetDesired(ctx, fmt.Sprintf("ns/s%d", i), routes[i])
		}
	}
}
