// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"net"
	"testing"

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
