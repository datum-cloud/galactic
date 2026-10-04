// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/crdnames"
)

// TestSeedFromAPIAppliesReadySlice verifies a well-formed, ready
// EndpointSlice found via the API reader is applied to Store just like a
// completed Reconcile would.
func TestSeedFromAPIAppliesReadySlice(t *testing.T) {
	scheme := newTestScheme(t)
	slice := readySlice("vpc1-att1", "fd00:99::1", "fd00::1")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice).Build()

	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	if err := SeedFromAPI(context.Background(), c, store); err != nil {
		t.Fatalf("SeedFromAPI: %v", err)
	}
	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1", got)
	}
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1", got)
	}
}

// TestSeedFromAPISkipsNotYetReady verifies a tenant-labeled EndpointSlice
// with no SID annotation yet (BuildDesiredRoute's (nil, nil) case) is
// skipped without error, same as Reconciler.Reconcile would.
func TestSeedFromAPISkipsNotYetReady(t *testing.T) {
	scheme := newTestScheme(t)
	slice := readySlice("vpc1-att1", "", "fd00::1") // no SID yet
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice).Build()

	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	if err := SeedFromAPI(context.Background(), c, store); err != nil {
		t.Fatalf("SeedFromAPI: %v", err)
	}
	if got := backend.vrfCount(); got != 0 {
		t.Errorf("vrfCount = %d, want 0 (not ready)", got)
	}
}

// TestSeedFromAPISkipsMalformedSlice verifies a selected-but-malformed
// EndpointSlice is logged and skipped rather than failing the whole seed
// pass, matching Reconciler.Reconcile's own handling of the same case.
func TestSeedFromAPISkipsMalformedSlice(t *testing.T) {
	scheme := newTestScheme(t)
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: testPodName,
			Labels:      map[string]string{crdnames.LabelTenantID: testMalformedTenantID},
			Annotations: map[string]string{crdnames.AnnotationTenantID: testMalformedTenantID},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice).Build()

	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	if err := SeedFromAPI(context.Background(), c, store); err != nil {
		t.Fatalf("SeedFromAPI: want nil error for malformed-but-selected slice, got %v", err)
	}
	if got := backend.vrfCount(); got != 0 {
		t.Errorf("vrfCount = %d, want 0", got)
	}
}

// TestSeedFromAPIIgnoresUnlabeledSlices verifies the tenant-label selector
// actually filters the List call, not just BuildDesiredRoute's own
// IsSelected check downstream -- an EndpointSlice with no tenant label at
// all must never even be considered.
func TestSeedFromAPIIgnoresUnlabeledSlices(t *testing.T) {
	scheme := newTestScheme(t)
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: "ns", Name: testPodName},
		AddressType: discoveryv1.AddressTypeIPv6,
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice).Build()

	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	if err := SeedFromAPI(context.Background(), c, store); err != nil {
		t.Fatalf("SeedFromAPI: %v", err)
	}
	if got := backend.vrfCount(); got != 0 {
		t.Errorf("vrfCount = %d, want 0 (unlabeled slice must be filtered by the selector)", got)
	}
}

// TestSeedFromAPIThenInventoryDoesNotOrphanLiveRoute reproduces the startup
// race flagged in PR #424's review: Store.Inventory used to be gated only
// on mgr.GetCache().WaitForCacheSync, which guarantees the informer's
// initial List landed in the cache but not that the controller's own
// Reconcile had drained the workqueue that same List fed. On a busy node
// at boot those could race, so Inventory could see a still-live pod's
// kernel route as orphaned and seed it under a synthetic "boot/..." key
// with its own independent grace period -- and once that synthetic entry's
// grace elapsed, Sweep would delete the underlying kernel route (routes are
// addressed by prefix+table, not by Store's map key) out from under the
// still-live pod, even though the real key (from the eventually-completed
// Reconcile) still believed it was installed.
//
// This test runs the fixed startup order directly -- SeedFromAPI, claiming
// the route from live API state, strictly before Inventory sees the
// matching kernel state -- with no Reconcile/SetDesired call standing in
// for "the controller's workqueue happened to drain in time". A long sweep
// afterward must never remove the route.
func TestSeedFromAPIThenInventoryDoesNotOrphanLiveRoute(t *testing.T) {
	scheme := newTestScheme(t)
	slice := readySlice("vpc1-att1", "fd00:99::1", "fd00::1")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice).Build()

	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	ctx := context.Background()
	if err := SeedFromAPI(ctx, c, store); err != nil {
		t.Fatalf("SeedFromAPI: %v", err)
	}
	if err := store.Inventory(ctx, time.Now()); err != nil {
		t.Fatalf("Inventory: %v", err)
	}

	// Sweep well past the grace period: the route must survive, tracked
	// under its real EndpointSlice key with no absentSince set -- never
	// seeded as a synthetic "boot/..." entry racing its own timer.
	store.Sweep(ctx, time.Now().Add(100*testGrace))
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1 (live route must survive the boot race)", got)
	}
	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1", got)
	}
}

// TestSeedFromAPIContinuesPastFailedSlice verifies one slice failing to apply
// does not stop the slices after it from loading, and is not returned as an
// error that would hold back the sweep.
func TestSeedFromAPIContinuesPastFailedSlice(t *testing.T) {
	a := readySlice("vpc1-att1", "fd00:99::1", "fd00::1")
	a.Name = "a"
	b := readySlice("vpc2-att1", "fd00:99::2", "fd00::2")
	b.Name = "b"
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(a, b).Build()

	backend := newFakeBackend()
	backend.failEnsureVRF = errTest
	store := NewStore(backend, testGrace, nil)

	if err := SeedFromAPI(context.Background(), c, store); err != nil {
		t.Fatalf("SeedFromAPI: %v, want nil", err)
	}
	for _, want := range []string{"EnsureVRF:vpc1", "EnsureVRF:vpc2"} {
		if !slices.Contains(backend.calls, want) {
			t.Errorf("calls = %v, want %q", backend.calls, want)
		}
	}
}

// TestSeedFromAPIFailedSliceKeepsHostRoute verifies a slice that fails to
// apply at startup, while its route from an earlier instance is still on the
// host, still claims that route: Inventory must not seed it as an orphan, and
// once the datapath is ready a sweep reinstalls it rather than removing it.
func TestSeedFromAPIFailedSliceKeepsHostRoute(t *testing.T) {
	slice := readySlice("vpc1-att1", "fd00:99::1", "fd00::1")
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(slice).Build()

	backend := newFakeBackend()
	backend.seedRoute(testVPC1, 7, mustPrefix(t, "fd00::1"), net.ParseIP("fd00:99::1"))
	backend.failEnsureVRF = errTest
	store := NewStore(backend, testGrace, nil)

	ctx := context.Background()
	if err := SeedFromAPI(ctx, c, store); err != nil {
		t.Fatalf("SeedFromAPI: %v", err)
	}
	if err := store.Inventory(ctx, time.Now()); err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	for key := range store.routes {
		if strings.HasPrefix(key, "boot/") {
			t.Errorf("Inventory seeded %q as an orphan; the failed slice should claim it", key)
		}
	}

	backend.failEnsureVRF = nil
	store.Sweep(ctx, time.Now().Add(100*testGrace))
	store.Sweep(ctx, time.Now().Add(200*testGrace))
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1", got)
	}
	if slices.ContainsFunc(backend.calls, func(c string) bool { return strings.HasPrefix(c, "Remove") }) {
		t.Errorf("calls = %v, want no removals of the live slice's state", backend.calls)
	}
	if r := store.routes["ns/"+testPodName]; r == nil || !r.installed || r.pending {
		t.Errorf("route state = %+v, want installed and not pending", r)
	}
}
