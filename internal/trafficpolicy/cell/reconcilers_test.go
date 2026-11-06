// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cell

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// TestBindingDeletedBeforeStatusApply: a binding deleted with its interface
// between the read and the status apply is not a reconcile error.
func TestBindingDeletedBeforeStatusApply(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{cloudv1alpha1.AddToScheme, galacticv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	binding := &galacticv1alpha1.TrafficPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "tenant"}}
	cl := interceptor.NewClient(fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding).Build(),
		interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, _ string, obj client.Object, _ client.Patch,
				_ ...client.SubResourcePatchOption,
			) error {
				return apierrors.NewNotFound(galacticv1alpha1.GroupVersion.WithResource("trafficpolicybindings").
					GroupResource(), obj.GetName())
			},
		})
	r := &BindingReconciler{Client: cl}
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(binding)})
	if err != nil {
		t.Fatalf("Reconcile error = %v, want nil", err)
	}
	if result != (ctrl.Result{}) {
		t.Fatalf("result = %+v, want none", result)
	}
}
