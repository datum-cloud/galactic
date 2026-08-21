// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
)

const (
	testPodName      = "web-0"
	testPodNamespace = "default"
	testPodUID       = types.UID("11111111-1111-1111-1111-111111111111")
	testPodAddr      = "fd00::1"

	// testStaleTenantID stands in for a value some earlier ADD wrote, shared
	// across this file's and ops_check_test.go's "stale value gets
	// refreshed/detected" cases.
	testStaleTenantID = "stale-tenant"
)

func testPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testPodNamespace,
			UID:       testPodUID,
		},
	}
}

func mustParseAddr(t *testing.T) net.IP {
	t.Helper()
	ip := net.ParseIP(testPodAddr)
	if ip == nil {
		t.Fatalf("net.ParseIP(%q) failed", testPodAddr)
	}
	return ip
}

func TestPublishEndpointSliceFreshPublish(t *testing.T) {
	testSID := netip.MustParseAddr("fd00:1::1")
	pod := testPod()
	k8s := fakeClient(pod)

	err := publishEndpointSlice(
		context.Background(), k8s, testPodNamespace, testPodName, testVPC, testAttachment,
		mustParseAddr(t), testSID,
	)
	if err != nil {
		t.Fatalf("publishEndpointSlice() = %v, want nil", err)
	}

	got := &discoveryv1.EndpointSlice{}
	if err := k8s.Get(context.Background(),
		client.ObjectKey{Name: testPodName, Namespace: testPodNamespace}, got); err != nil {
		t.Fatalf("get EndpointSlice after publish: %v", err)
	}

	wantTenantID := crdnames.TenantIdentifier(testVPC, testAttachment)
	if got.Labels[crdnames.LabelTenantID] != wantTenantID {
		t.Errorf("label %s = %q, want %q", crdnames.LabelTenantID, got.Labels[crdnames.LabelTenantID], wantTenantID)
	}
	if got.Annotations[crdnames.AnnotationTenantID] != wantTenantID {
		t.Errorf("annotation %s = %q, want %q",
			crdnames.AnnotationTenantID, got.Annotations[crdnames.AnnotationTenantID], wantTenantID)
	}
	if got.Annotations[crdnames.AnnotationSID] != testSID.String() {
		t.Errorf("annotation %s = %q, want %q",
			crdnames.AnnotationSID, got.Annotations[crdnames.AnnotationSID], testSID.String())
	}
	if got.AddressType != discoveryv1.AddressTypeIPv6 {
		t.Errorf("AddressType = %q, want %q", got.AddressType, discoveryv1.AddressTypeIPv6)
	}
	if len(got.Endpoints) != 1 || len(got.Endpoints[0].Addresses) != 1 || got.Endpoints[0].Addresses[0] != testPodAddr {
		t.Errorf("Endpoints = %+v, want a single endpoint with address %q", got.Endpoints, testPodAddr)
	}
	if got.Endpoints[0].Conditions.Ready == nil || !*got.Endpoints[0].Conditions.Ready {
		t.Errorf("Endpoints[0].Conditions.Ready = %v, want true", got.Endpoints[0].Conditions.Ready)
	}

	owners := got.GetOwnerReferences()
	if len(owners) != 1 || owners[0].Name != testPodName || owners[0].UID != testPodUID {
		t.Errorf("OwnerReferences = %+v, want a single owner referencing pod %s (UID %s)",
			owners, testPodName, testPodUID)
	}
	if owners[0].Controller != nil && *owners[0].Controller {
		t.Error("owner reference Controller = true, want false/nil (SetOwnerReference, not SetControllerReference)")
	}
}

func TestPublishEndpointSliceSRv6NotConfiguredOmitsSID(t *testing.T) {
	pod := testPod()
	k8s := fakeClient(pod)

	err := publishEndpointSlice(
		context.Background(), k8s, testPodNamespace, testPodName, testVPC, testAttachment,
		mustParseAddr(t), netip.Addr{}, // zero value: SID not computed
	)
	if err != nil {
		t.Fatalf("publishEndpointSlice() = %v, want nil", err)
	}

	got := &discoveryv1.EndpointSlice{}
	if err := k8s.Get(context.Background(),
		client.ObjectKey{Name: testPodName, Namespace: testPodNamespace}, got); err != nil {
		t.Fatalf("get EndpointSlice after publish: %v", err)
	}
	if _, ok := got.Annotations[crdnames.AnnotationSID]; ok {
		t.Errorf("annotation %s present = %q, want absent when SID was not computed",
			crdnames.AnnotationSID, got.Annotations[crdnames.AnnotationSID])
	}
}

func TestPublishEndpointSliceUpdateInPlace(t *testing.T) {
	testSID := netip.MustParseAddr("fd00:1::1")
	pod := testPod()
	existing := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testPodNamespace,
			Labels:    map[string]string{crdnames.LabelTenantID: testStaleTenantID},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"fd00::dead"}}},
	}
	k8s := fakeClient(pod, existing)

	if err := publishEndpointSlice(
		context.Background(), k8s, testPodNamespace, testPodName, testVPC, testAttachment,
		mustParseAddr(t), testSID,
	); err != nil {
		t.Fatalf("publishEndpointSlice() = %v, want nil", err)
	}

	got := &discoveryv1.EndpointSlice{}
	if err := k8s.Get(context.Background(),
		client.ObjectKey{Name: testPodName, Namespace: testPodNamespace}, got); err != nil {
		t.Fatalf("get EndpointSlice after update: %v", err)
	}
	wantTenantID := crdnames.TenantIdentifier(testVPC, testAttachment)
	if got.Labels[crdnames.LabelTenantID] != wantTenantID {
		t.Errorf("label %s = %q, want %q (refreshed)",
			crdnames.LabelTenantID, got.Labels[crdnames.LabelTenantID], wantTenantID)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].Addresses[0] != testPodAddr {
		t.Errorf("Endpoints = %+v, want the refreshed address %q", got.Endpoints, testPodAddr)
	}
}

func TestPublishEndpointSliceNamingCollisionNotOverwritten(t *testing.T) {
	testSID := netip.MustParseAddr("fd00:1::1")
	pod := testPod()
	foreign := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testPodNamespace,
			Labels:    map[string]string{"kubernetes.io/service-name": "some-service"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	k8s := fakeClient(pod, foreign)

	err := publishEndpointSlice(
		context.Background(), k8s, testPodNamespace, testPodName, testVPC, testAttachment,
		mustParseAddr(t), testSID,
	)
	if err == nil {
		t.Fatal("publishEndpointSlice() = nil, want an error for a non-tenant-labeled name collision")
	}
	if !strings.Contains(err.Error(), crdnames.LabelTenantID) {
		t.Errorf("error %q does not mention %s", err, crdnames.LabelTenantID)
	}

	got := &discoveryv1.EndpointSlice{}
	if err := k8s.Get(context.Background(),
		client.ObjectKey{Name: testPodName, Namespace: testPodNamespace}, got); err != nil {
		t.Fatalf("get EndpointSlice after refused publish: %v", err)
	}
	if got.AddressType != discoveryv1.AddressTypeIPv4 {
		t.Errorf("foreign EndpointSlice was mutated: AddressType = %q, want unchanged %q",
			got.AddressType, discoveryv1.AddressTypeIPv4)
	}
}

func TestPublishEndpointSliceOwningPodNotFound(t *testing.T) {
	testSID := netip.MustParseAddr("fd00:1::1")
	k8s := fakeClient()

	err := publishEndpointSlice(
		context.Background(), k8s, testPodNamespace, testPodName, testVPC, testAttachment,
		mustParseAddr(t), testSID,
	)
	if err == nil {
		t.Fatal("publishEndpointSlice() = nil, want an error when the owning Pod does not exist")
	}
	if client.IgnoreNotFound(err) != nil && !apierrors.IsNotFound(client.IgnoreNotFound(err)) {
		t.Errorf("expected error to wrap a not-found status, got: %v", err)
	}
}

func TestDeleteEndpointSlice(t *testing.T) {
	t.Run("deletes an existing EndpointSlice", func(t *testing.T) {
		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Name: testPodName, Namespace: testPodNamespace},
		}
		k8s := fakeClient(slice)

		if err := deleteEndpointSlice(context.Background(), k8s, testPodNamespace, testPodName); err != nil {
			t.Fatalf("deleteEndpointSlice() = %v, want nil", err)
		}

		err := k8s.Get(context.Background(), client.ObjectKey{Name: testPodName, Namespace: testPodNamespace},
			&discoveryv1.EndpointSlice{})
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected NotFound after delete, got: %v", err)
		}
	})

	t.Run("idempotent when EndpointSlice does not exist", func(t *testing.T) {
		k8s := fakeClient()

		if err := deleteEndpointSlice(context.Background(), k8s, testPodNamespace, testPodName); err != nil {
			t.Fatalf("deleteEndpointSlice() on absent object = %v, want nil", err)
		}
	})
}
