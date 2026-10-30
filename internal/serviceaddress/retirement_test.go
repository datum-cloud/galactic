// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceaddress

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "go.datum.net/galactic/api/network/v1alpha1"
)

func TestPreemptiveRetirementWithoutGateways(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation int64
		pending    bool
		want       bool
	}{
		{"NeverActivated", 1, false, true}, {"HistoricalAllocation", 2, false, false}, {"BindingPending", 1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			if err := api.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			address := &api.NetworkServiceAddress{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "retired",
					Namespace:  "project",
					UID:        "anchor",
					Generation: tc.generation,
				},
				Spec: api.NetworkServiceAddressSpec{
					Retired:    true,
					VIPAddress: "2001:db8::1",
					Group:      api.NetworkServiceAddressGroup{UID: "claim", Generation: 1, Revision: "retired"},
				},
			}
			builder := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(address).WithObjects(address)
			if tc.pending {
				builder = builder.WithObjects(
					&api.ServiceVIPBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "gateways"},
						Spec: api.ServiceVIPBindingSpec{
							SourceRef: &api.ServiceVIPBindingSourceReference{AllocationUID: "claim"},
						},
					},
				)
			}
			c := builder.Build()
			r := &RetirementReconciler{Client: c, APIReader: c}
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(address)}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
				t.Fatal(err)
			}
			if got := meta.IsStatusConditionTrue(address.Status.Conditions, api.ConditionTypeAddressRetired); got != tc.want {
				t.Fatalf("retired=%t want=%t", got, tc.want)
			}
			if tc.want && len(address.Finalizers) == 0 {
				t.Fatal("terminal authority was not retained")
			}
		})
	}
}
