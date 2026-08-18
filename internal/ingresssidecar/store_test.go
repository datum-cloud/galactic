// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
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

// TestStoreRouteAndVRFAppear verifies a pod's first appearance creates both
// its VRF (per §1: one per VPC) and its own route.
func TestStoreRouteAndVRFAppear(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: "vpc1", Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
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

	first := &DesiredRoute{VPC: "vpc1", Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	second := &DesiredRoute{VPC: "vpc1", Prefix: mustPrefix(t, "fd00::2"), SID: net.ParseIP("fd00:99::2")}

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

	desired := &DesiredRoute{VPC: "vpc1", Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
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

	desired := &DesiredRoute{VPC: "vpc1", Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
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

	desired := &DesiredRoute{VPC: "vpc1", Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
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
	backend.seedRoute("vpc1", 5, prefix, net.ParseIP("fd00:99::1"))

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
	desired := &DesiredRoute{VPC: "vpc1", Prefix: prefix, SID: net.ParseIP("fd00:99::1")}
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

	desired := &DesiredRoute{VPC: "vpc1", Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
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
