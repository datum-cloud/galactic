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
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// laggingCache makes the reconciler's cached client miss every
// BGPAdvertisement, as an informer does just after a fast delete and
// recreate, while the API still serves it.
func laggingCache(f *ownershipFixture) {
	f.reconciler.Client = interceptor.NewClient(f.client.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption,
		) error {
			if _, ok := obj.(*bgpv1alpha1.BGPAdvertisement); ok {
				return apierrors.NewNotFound(schema.GroupResource{Resource: "bgpadvertisements"}, key.Name)
			}
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*bgpv1alpha1.BGPAdvertisementList); ok {
				return nil
			}
			return c.List(ctx, list, opts...)
		},
	})
}

func TestCacheLagNotFoundKeepsDeliveryStatus(t *testing.T) {
	f := newOwnershipFixture(t, false)
	f.reconcile(t, f.tenantAdv)
	laggingCache(f)
	f.reconciler.APIReader = f.client
	f.reconcile(t, f.tenantAdv)
	status := f.attachmentStatus(t)
	if status.Node == "" || status.PodSubnet != f.attachment.Status.PodSubnet ||
		!meta.IsStatusConditionTrue(status.Conditions, cloudv1alpha1.ConditionTypeProgrammed) {
		t.Fatalf("cache-lag NotFound cleared live delivery status: %+v", status)
	}
}

func TestConfirmedWithdrawalClearsDeliveryStatus(t *testing.T) {
	f := newOwnershipFixture(t, false)
	f.reconcile(t, f.tenantAdv)
	f.reconciler.APIReader = f.client
	if err := f.client.Delete(context.Background(), f.tenantAdv); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, f.tenantAdv)
	status := f.attachmentStatus(t)
	if status.Node != "" || !meta.IsStatusConditionFalse(status.Conditions, cloudv1alpha1.ConditionTypeProgrammed) {
		t.Fatalf("confirmed withdrawal kept delivery status: %+v", status)
	}
}
