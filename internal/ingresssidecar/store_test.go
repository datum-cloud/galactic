// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func mustPrefix(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad IP %q", s)
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

const testGrace = 10 * time.Second

// testVPC1, testPodName, and testMalformedTenantID are fixture values
// shared across this package's tests.
const (
	testVPC1    = "vpc1"
	testPodName = "pod-a"
	// testMalformedTenantID has no "-" separator, so
	// crdnames.ParseTenantIdentifier rejects it -- used by both
	// controller_test.go and seed_test.go to build a selected-but-
	// malformed EndpointSlice fixture.
	testMalformedTenantID = "novalidseparator"
)

// TestStoreRouteAndVRFAppear verifies a pod's first appearance creates both
// its VRF (per §1: one per VPC) and its own route.
func TestStoreRouteAndVRFAppear(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}

	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1", got)
	}
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1", got)
	}
}

// TestStoreSecondAttachmentSharesVRF verifies a second pod on the same VPC
// (a different attachment) reuses the existing VRF rather than creating a
// second one, and doesn't disturb the first pod's own route — the core
// claim of §1's VRF-granularity correction.
func TestStoreSecondAttachmentSharesVRF(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	first := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	second := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::2"), SID: net.ParseIP("fd00:99::2")}

	if err := store.SetDesired(ctx, "ns/pod-a", first); err != nil {
		t.Fatalf("SetDesired(pod-a): %v", err)
	}
	if err := store.SetDesired(ctx, "ns/pod-b", second); err != nil {
		t.Fatalf("SetDesired(pod-b): %v", err)
	}

	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1 (shared VRF)", got)
	}
	if got := backend.routeCount(); got != 2 {
		t.Errorf("routeCount = %d, want 2 (independent routes)", got)
	}

	// Removing pod-b's route must not touch pod-a's, or the shared VRF.
	if err := store.SetDesired(ctx, "ns/pod-b", nil); err != nil {
		t.Fatalf("SetDesired(pod-b, nil): %v", err)
	}
	store.Sweep(ctx, time.Now().Add(2*testGrace))

	if got := backend.vrfCount(); got != 1 {
		t.Errorf("after pod-b removal: vrfCount = %d, want 1 (pod-a still live)", got)
	}
	if got := backend.routeCount(); got != 1 {
		t.Errorf("after pod-b removal: routeCount = %d, want 1 (pod-a's route untouched)", got)
	}
}

// TestStoreRouteTeardownGrace verifies a route is not removed before its
// grace period elapses, and is removed once it has.
func TestStoreRouteTeardownGrace(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}
	if err := store.SetDesired(ctx, "ns/pod-a", nil); err != nil {
		t.Fatalf("SetDesired(nil): %v", err)
	}

	// Sweep well before the grace period elapses: route (and its VRF)
	// must still be installed.
	store.Sweep(ctx, time.Now().Add(1*time.Second))
	if got := backend.routeCount(); got != 1 {
		t.Errorf("mid-grace: routeCount = %d, want 1 (not yet torn down)", got)
	}
	if got := backend.vrfCount(); got != 1 {
		t.Errorf("mid-grace: vrfCount = %d, want 1 (route's own grace still pending)", got)
	}

	// Sweep well after: both should be gone. The VRF's own grace only
	// starts once the route is actually swept, so sweep twice with time
	// advanced far enough past two grace periods.
	store.Sweep(ctx, time.Now().Add(2*testGrace))
	store.Sweep(ctx, time.Now().Add(4*testGrace))
	if got := backend.routeCount(); got != 0 {
		t.Errorf("post-grace: routeCount = %d, want 0", got)
	}
	if got := backend.vrfCount(); got != 0 {
		t.Errorf("post-grace: vrfCount = %d, want 0 (last pod gone)", got)
	}
}

// TestStoreVRFOutlivesRouteGrace verifies the VRF's own teardown never
// fires while any of its routes are still within their own grace period —
// §9 item 1's "must not overlap" requirement.
func TestStoreVRFOutlivesRouteGrace(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}
	if err := store.SetDesired(ctx, "ns/pod-a", nil); err != nil {
		t.Fatalf("SetDesired(nil): %v", err)
	}

	// A single sweep just past the route's own grace: the route is removed
	// in this same pass, but the VRF's grace clock only starts now — it
	// must NOT be removed in this same sweep.
	store.Sweep(ctx, time.Now().Add(testGrace+time.Millisecond))
	if got := backend.routeCount(); got != 0 {
		t.Errorf("routeCount = %d, want 0", got)
	}
	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1 (VRF grace must start only now, not fire in the same sweep)", got)
	}
}

// TestStoreReactivationCancelsTeardown verifies a route reappearing before
// its grace period elapses cancels the pending teardown.
func TestStoreReactivationCancelsTeardown(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}
	if err := store.SetDesired(ctx, "ns/pod-a", nil); err != nil {
		t.Fatalf("SetDesired(nil): %v", err)
	}
	// Reactivate before any sweep has torn it down.
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired(reactivate): %v", err)
	}

	store.Sweep(ctx, time.Now().Add(4*testGrace))
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1 (reactivation should have cancelled teardown)", got)
	}
	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1", got)
	}
}

// TestStoreInventorySeedsOrphan verifies Inventory picks up a kernel VRF/
// route with no corresponding tracked state and gives it a fresh grace
// period, rather than tearing it down immediately or ignoring it forever.
func TestStoreInventorySeedsOrphan(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	prefix := mustPrefix(t, "fd00::1")
	backend.seedRoute(testVPC1, 5, prefix, net.ParseIP("fd00:99::1"))

	if err := store.Inventory(ctx, time.Now()); err != nil {
		t.Fatalf("Inventory: %v", err)
	}

	// Not torn down immediately.
	store.Sweep(ctx, time.Now().Add(1*time.Second))
	if got := backend.routeCount(); got != 1 {
		t.Errorf("mid-grace: routeCount = %d, want 1", got)
	}

	// Torn down once its grace period (started at Inventory time) elapses,
	// with no SetDesired call ever having reclaimed it.
	store.Sweep(ctx, time.Now().Add(2*testGrace))
	store.Sweep(ctx, time.Now().Add(4*testGrace))
	if got := backend.routeCount(); got != 0 {
		t.Errorf("post-grace: routeCount = %d, want 0 (truly orphaned)", got)
	}
	if got := backend.vrfCount(); got != 0 {
		t.Errorf("post-grace: vrfCount = %d, want 0", got)
	}
}

// TestStoreInventorySkipsKnownRoute verifies Inventory does not
// double-track (and therefore does not risk deleting out from under) a
// route a live EndpointSlice's reconcile already claimed via SetDesired.
func TestStoreInventorySkipsKnownRoute(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	prefix := mustPrefix(t, "fd00::1")
	desired := &DesiredRoute{VPC: testVPC1, Prefix: prefix, SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}

	// Inventory runs after the reconcile already claimed this exact
	// (vpc, prefix) — the fake backend now genuinely has it installed.
	if err := store.Inventory(ctx, time.Now()); err != nil {
		t.Fatalf("Inventory: %v", err)
	}

	// A very long sweep must not remove it: it's tracked under the real
	// key with no absentSince set, not under a synthetic boot/ key racing
	// its own independent grace period.
	store.Sweep(ctx, time.Now().Add(100*testGrace))
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1 (live route must never be torn down)", got)
	}
}

// TestStoreEnsureVRFErrorNotTracked verifies a failed EnsureVRF call
// doesn't leave a route marked installed with no backing kernel state.
func TestStoreEnsureVRFErrorNotTracked(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	backend.failEnsureVRF = errTest
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err == nil {
		t.Fatal("SetDesired: want error, got nil")
	}
	if got := backend.routeCount(); got != 0 {
		t.Errorf("routeCount = %d, want 0 (route must not be installed without its VRF)", got)
	}
}

var errTest = &testError{"boom"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// TestStoreSharedPrefixSurvivesSiblingTeardown verifies that tearing down one
// of two EndpointSlices sharing a backend address leaves the other's kernel
// route in place. The platform publishes both a pod-owned slice and a
// federated copy of it, so a shared address is the ordinary case.
func TestStoreSharedPrefixSurvivesSiblingTeardown(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	shared := func() *DesiredRoute {
		return &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	}
	if err := store.SetDesired(ctx, "ns/pod-a", shared()); err != nil {
		t.Fatalf("SetDesired(pod-a): %v", err)
	}
	if err := store.SetDesired(ctx, "ns/projected-pod-a", shared()); err != nil {
		t.Fatalf("SetDesired(projected-pod-a): %v", err)
	}
	if err := store.SetDesired(ctx, "ns/projected-pod-a", nil); err != nil {
		t.Fatalf("SetDesired(projected-pod-a, nil): %v", err)
	}

	store.Sweep(ctx, time.Now().Add(2*testGrace))

	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1 (live slice still needs the route)", got)
	}
	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1", got)
	}
}

// testGenLoaded and testGenReloaded are fake DatapathGeneration values for a
// datapath before and after the CNI control daemon reloads it.
const (
	testGenLoaded   = "1/1"
	testGenReloaded = "2/2"
)

// callsSince returns the backend calls logged after the first n.
func (f *fakeBackend) callsSince(n int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls[n:]...)
}

func (f *fakeBackend) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// TestStoreSweepReappliesAfterDatapathReload is issue #609's regression
// test: a reload that empties the shared eBPF maps while the route's
// EndpointSlice stays unchanged must be repaired by the next Sweep, not left
// missing until this process restarts.
func TestStoreSweepReappliesAfterDatapathReload(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	backend.generation = testGenLoaded
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}

	backend.reloadDatapath()
	before := backend.callCount()
	store.Sweep(ctx, time.Now())

	got := backend.callsSince(before)
	want := []string{"EnsureVRF:" + testVPC1, "EnsureRoute:1/fd00::1/128"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("calls after reload = %v, want %v", got, want)
	}
	if n := backend.routeCount(); n != 1 {
		t.Errorf("routeCount after reapply = %d, want 1", n)
	}
}

// TestStoreSweepNoReapplyWhenGenerationStable verifies an unchanged
// datapath costs no backend writes on any Sweep.
func TestStoreSweepNoReapplyWhenGenerationStable(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	backend.generation = testGenLoaded
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}

	before := backend.callCount()
	for range 3 {
		store.Sweep(ctx, time.Now())
	}
	if got := backend.callsSince(before); len(got) != 0 {
		t.Errorf("calls with a stable generation = %v, want none", got)
	}
}

// TestStoreSweepGenerationReadFailureDoesNothing verifies an unreadable
// generation, meaning no datapath is loaded at all, neither reapplies nor
// disturbs the stored generation, so the reapply fires once it loads again.
func TestStoreSweepGenerationReadFailureDoesNothing(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	backend.generation = testGenLoaded
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}

	backend.reloadDatapath()
	backend.failGeneration = errors.New("pinned map not found")
	before := backend.callCount()
	store.Sweep(ctx, time.Now())
	if got := backend.callsSince(before); len(got) != 0 {
		t.Fatalf("calls with an unreadable generation = %v, want none", got)
	}

	backend.failGeneration = nil
	store.Sweep(ctx, time.Now())
	if n := backend.routeCount(); n != 1 {
		t.Errorf("routeCount once the generation is readable again = %d, want 1", n)
	}
}

// TestStoreReapplySkipsRoutesInGrace verifies a reload does not reinstall a
// route already waiting out its teardown grace period.
func TestStoreReapplySkipsRoutesInGrace(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	backend.generation = testGenLoaded
	store := NewStore(backend, testGrace, nil)

	live := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	leaving := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::2"), SID: net.ParseIP("fd00:99::2")}
	for key, d := range map[string]*DesiredRoute{"ns/pod-a": live, "ns/pod-b": leaving} {
		if err := store.SetDesired(ctx, key, d); err != nil {
			t.Fatalf("SetDesired %s: %v", key, err)
		}
	}
	if err := store.SetDesired(ctx, "ns/pod-b", nil); err != nil {
		t.Fatalf("SetDesired nil: %v", err)
	}

	backend.reloadDatapath()
	before := backend.callCount()
	store.Sweep(ctx, time.Now())

	for _, c := range backend.callsSince(before) {
		if c == "EnsureRoute:1/fd00::2/128" {
			t.Errorf("reapply reinstalled a route within its grace period: %v", backend.callsSince(before))
		}
	}
	if n := backend.routeCount(); n != 1 {
		t.Errorf("routeCount after reapply = %d, want 1 (the live route only)", n)
	}
}

// TestStoreReapplyRetriesOnFailure verifies a reapply pass that fails is
// retried on the next Sweep even though the generation has not moved again.
func TestStoreReapplyRetriesOnFailure(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	backend.generation = testGenLoaded
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}

	backend.reloadDatapath()
	backend.failEnsureRoute = errors.New("map write failed")
	store.Sweep(ctx, time.Now())
	if n := backend.routeCount(); n != 0 {
		t.Fatalf("routeCount after failed reapply = %d, want 0", n)
	}

	backend.failEnsureRoute = nil
	store.Sweep(ctx, time.Now())
	if n := backend.routeCount(); n != 1 {
		t.Fatalf("routeCount after retried reapply = %d, want 1", n)
	}

	before := backend.callCount()
	store.Sweep(ctx, time.Now())
	if got := backend.callsSince(before); len(got) != 0 {
		t.Errorf("calls once the retry succeeded = %v, want none", got)
	}
}
