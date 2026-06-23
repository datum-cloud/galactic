// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// BGPPolicyReconciler watches BGPPolicy resources and enqueues the
// owning BGPRouter(s).
type BGPPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile enqueues the owning BGPRouter(s) when a BGPPolicy changes.
func (r *BGPPolicyReconciler) Reconcile(_ context.Context, _ ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

// SetupWithManager registers the BGPPolicyReconciler with the manager.
func (r *BGPPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPPolicy{}).
		Named("bgppolicy").
		Complete(r)
}

// policyToRouterRequests maps a BGPPolicy to reconcile.Requests for its
// owning BGPRouter(s).
func policyToRouterRequests(ctx context.Context, c client.Client, obj client.Object) []reconcile.Request {
	policy, ok := obj.(*bgpv1alpha1.BGPPolicy)
	if !ok {
		return nil
	}
	return enqueueRoutersForTarget(ctx, c, policy.Namespace,
		policy.Spec.RouterRef, policy.Spec.RouterSelector,
		"BGPPolicy/"+policy.Name,
	)
}
