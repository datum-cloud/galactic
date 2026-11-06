/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package controller

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

// failInterfaceStatus makes every interface status write return err, the way
// a write from a stale cached copy, or to a deleted interface, does.
func failInterfaceStatus(f *ownershipFixture, err error) {
	f.reconciler.Client = interceptor.NewClient(f.client.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption,
		) error {
			if _, ok := obj.(*networkingv1alpha.NetworkInterface); ok {
				return err
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
}

// TestStatusConflictRetriesWithoutError: losing the interface status write
// to another writer is normal convergence, so it requeues instead of
// counting as a reconcile error.
func TestStatusConflictRetriesWithoutError(t *testing.T) {
	f := newOwnershipFixture(t, false)
	failInterfaceStatus(f, apierrors.NewConflict(
		schema.GroupResource{Group: networkingv1alpha.GroupVersion.Group, Resource: "networkinterfaces"},
		f.iface.Name, nil))
	result, err := f.reconciler.Reconcile(context.Background(), ctrlreconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: f.tenantAdv.Namespace, Name: f.tenantAdv.Name},
	})
	if err != nil {
		t.Fatalf("Reconcile error = %v, want nil", err)
	}
	if result != (ctrl.Result{Requeue: true}) {
		t.Fatalf("result = %+v, want a requeue", result)
	}
}

// TestDeletedInterfaceIsNotAnError: an interface deleted after it was read
// leaves nothing to certify.
func TestDeletedInterfaceIsNotAnError(t *testing.T) {
	f := newOwnershipFixture(t, false)
	failInterfaceStatus(f, apierrors.NewNotFound(
		schema.GroupResource{Group: networkingv1alpha.GroupVersion.Group, Resource: "networkinterfaces"},
		f.iface.Name))
	f.reconcile(t, f.tenantAdv)
}
