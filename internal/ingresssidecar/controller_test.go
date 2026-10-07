// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"net"
	"testing"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/crdnames"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add clientgoscheme: %v", err)
	}
	return scheme
}

// TestReconcilerAppliesDesiredRoute verifies a straightforward reconcile of
// an existing, well-formed EndpointSlice installs its VRF and route.
func TestReconcilerAppliesDesiredRoute(t *testing.T) {
	scheme := newTestScheme(t)
	slice := readySlice("vpc1-att1", "fd00:1234::1", "fd00::abcd")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(slice).Build()

	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)
	r := &Reconciler{Client: c, Store: store}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "ns", Name: testPodName},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1", got)
	}
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1", got)
	}
}

// TestReconcilerDeletedSliceStartsGrace verifies a Reconcile against a
// missing EndpointSlice marks its route absent (starting its teardown
// grace) rather than erroring or removing it synchronously.
func TestReconcilerDeletedSliceStartsGrace(t *testing.T) {
	scheme := newTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)
	if err := store.SetDesired(context.Background(), "ns/pod-a",
		&DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}); err != nil {
		t.Fatalf("seed SetDesired: %v", err)
	}
	r := &Reconciler{Client: c, Store: store}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: testPodName}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Not torn down synchronously -- still installed immediately after.
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1 (grace not yet elapsed)", got)
	}
}

// TestReconcilerMalformedSliceDoesNotError verifies a selected-but-malformed
// EndpointSlice is dropped (logged, not retried forever) rather than
// returned as a Reconcile error.
func TestReconcilerMalformedSliceDoesNotError(t *testing.T) {
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
	r := &Reconciler{Client: c, Store: store}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "ns", Name: testPodName},
	})
	if err != nil {
		t.Fatalf("Reconcile: want nil error for malformed-but-selected slice, got %v", err)
	}
	if got := backend.vrfCount(); got != 0 {
		t.Errorf("vrfCount = %d, want 0", got)
	}
}

// TestRunStartupSweepsAfterFailedSeed verifies a slice failing to apply at
// startup, as it does when the sidecar starts before the CNI has loaded the
// datapath, neither stops the periodic sweep nor stays failed: an orphaned VRF
// left by an earlier instance is still torn down, and the failed slice is
// installed once the datapath is ready.
func TestRunStartupSweepsAfterFailedSeed(t *testing.T) {
	slice := readySlice("vpc1-att1", "fd00:99::1", "fd00::1")
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(slice).Build()

	backend := newFakeBackend()
	backend.seedRoute("orphan", 9, mustPrefix(t, "fd00::9"), net.ParseIP("fd00:99::9"))
	backend.failEnsureVRF = errTest
	store := NewStore(backend, 20*time.Millisecond, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunStartup(ctx, c, store, 5*time.Millisecond)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitFor(t, "orphaned VRF torn down", func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		_, ok := backend.vrfs["orphan"]
		return !ok
	})

	backend.mu.Lock()
	backend.failEnsureVRF = nil
	backend.mu.Unlock()

	waitFor(t, "failed slice installed", func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		_, vrf := backend.vrfs[testVPC1]
		return vrf && len(backend.routes) == 1
	})
}

// TestRunStartupPrunesAfterInventory verifies the startup prune runs once,
// after Inventory, so the VRFs the pod already holds are in its keep set.
func TestRunStartupPrunesAfterInventory(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()

	backend := newFakeBackend()
	backend.seedRoute("existing", 9, mustPrefix(t, "fd00::9"), net.ParseIP("fd00:99::9"))
	store := NewStore(backend, time.Hour, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunStartup(ctx, c, store, time.Hour)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitFor(t, "startup prune", func() bool {
		backend.mu.Lock()
		defer backend.mu.Unlock()
		return len(backend.pruned) == 1
	})
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if _, ok := backend.pruned[0][9]; !ok {
		t.Errorf("keep = %v, want it to hold the inventoried VRF's table 9", backend.pruned[0])
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
