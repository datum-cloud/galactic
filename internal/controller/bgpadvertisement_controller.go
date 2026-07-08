// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// BGPAdvertisementReconciler watches BGPAdvertisement resources and enqueues
// the owning BGPRouter.
type BGPAdvertisementReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile is a no-op. BGPAdvertisement changes are forwarded to the
// BGPRouterReconciler via a Watches call in its SetupWithManager.
func (r *BGPAdvertisementReconciler) Reconcile(_ context.Context, _ ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

// SetupWithManager registers the BGPAdvertisementReconciler with the manager.
func (r *BGPAdvertisementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPAdvertisement{}).
		Named("bgpadvertisement").
		Complete(r)
}
