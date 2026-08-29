// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/crdnames"
)

const testTenantNamespace = "ns-tenant"

func TestActiveVPCsFromEndpointSlices(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add to scheme: %v", err)
	}

	tenantSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tenant-slice",
			Namespace: testTenantNamespace,
			Labels: map[string]string{
				crdnames.LabelTenantID: "2-JL",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
	}
	// A slice with the same label key but a malformed value (no "-") must
	// not blow up the sweep or silently claim an empty-string VPC.
	malformedSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "malformed-slice",
			Namespace: testTenantNamespace,
			Labels: map[string]string{
				crdnames.LabelTenantID: "malformed",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
	}
	// A slice with no tenant label at all must not appear in the result —
	// confirms the List call's own label selector, not just the parse step.
	untaggedSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "untagged-slice",
			Namespace: testTenantNamespace,
		},
		AddressType: discoveryv1.AddressTypeIPv6,
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tenantSlice, malformedSlice, untaggedSlice).
		Build()

	got, err := activeVPCsFromEndpointSlices(context.Background(), fakeClient)
	if err != nil {
		t.Fatalf("activeVPCsFromEndpointSlices: %v", err)
	}

	if !vpcInSet(got, "2") {
		t.Errorf("activeVPCsFromEndpointSlices() = %v, want VPC %q present", got, "2")
	}
	if len(got) != 1 {
		t.Errorf("activeVPCsFromEndpointSlices() = %v, want exactly one VPC "+
			"(malformed/untagged slices must not contribute)", got)
	}
}

func TestActiveVPCsFromEndpointSlices_NoSlices(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add to scheme: %v", err)
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	got, err := activeVPCsFromEndpointSlices(context.Background(), fakeClient)
	if err != nil {
		t.Fatalf("activeVPCsFromEndpointSlices: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("activeVPCsFromEndpointSlices() = %v, want empty", got)
	}
}
