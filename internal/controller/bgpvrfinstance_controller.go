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

// BGPVRFInstanceReconciler watches BGPVRFInstance resources and enqueues
// the owning BGPRouter.
type BGPVRFInstanceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile enqueues the owning BGPRouter when a BGPVRFInstance changes.
func (r *BGPVRFInstanceReconciler) Reconcile(_ context.Context, _ ctrl.Request) (ctrl.Result, error) {
	// BGPVRFInstance changes are handled by enqueuing the owning router in
	// SetupWithManager via EnqueueRequestsFromMapFunc. This reconciler is
	// intentionally empty — the work is done by BGPRouterReconciler.
	return ctrl.Result{}, nil
}

// SetupWithManager registers the BGPVRFInstanceReconciler with the manager.
func (r *BGPVRFInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPVRFInstance{}).
		Watches(&bgpv1alpha1.BGPVRFInstance{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []reconcile.Request {
				vrf, ok := obj.(*bgpv1alpha1.BGPVRFInstance)
				if !ok {
					return nil
				}
				if vrf.Spec.RouterRef == nil {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: types.NamespacedName{
						Namespace: vrf.Namespace,
						Name:      vrf.Spec.RouterRef.Name,
					},
				}}
			},
		)).
		Named("bgpvrfinstance").
		Complete(r)
}
