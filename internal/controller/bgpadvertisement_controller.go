// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// BGPAdvertisementReconciler watches BGPAdvertisement resources and enqueues
// the owning BGPRouter.
type BGPAdvertisementReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile enqueues the owning BGPRouter when a BGPAdvertisement changes.
func (r *BGPAdvertisementReconciler) Reconcile(_ context.Context, _ ctrl.Request) (ctrl.Result, error) {
	// BGPAdvertisement changes are handled by enqueuing the owning router in
	// SetupWithManager via EnqueueRequestsFromMapFunc. This reconciler is
	// intentionally empty — the work is done by BGPRouterReconciler.
	return ctrl.Result{}, nil
}

// SetupWithManager registers the BGPAdvertisementReconciler with the manager.
func (r *BGPAdvertisementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPAdvertisement{}).
		Watches(&bgpv1alpha1.BGPAdvertisement{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []reconcile.Request {
				adv, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
				if !ok {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: types.NamespacedName{
						Namespace: adv.Namespace,
						Name:      adv.Spec.RouterRef.Name,
					},
				}}
			},
		)).
		Named("bgpadvertisement").
		Complete(r)
}
