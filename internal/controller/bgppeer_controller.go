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

// BGPPeerReconciler watches BGPPeer resources and enqueues the owning BGPRouter(s).
type BGPPeerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile is intentionally empty. BGPPeer changes trigger BGPRouter
// reconciles via the BGPRouterReconciler's BGPPeer watch.
func (r *BGPPeerReconciler) Reconcile(_ context.Context, _ ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

// SetupWithManager registers the BGPPeerReconciler with the manager.
func (r *BGPPeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPPeer{}).
		Named("bgppeer").
		Complete(r)
}

// peerToRouterRequests maps a BGPPeer to reconcile.Requests for its owning BGPRouter(s).
func peerToRouterRequests(ctx context.Context, c client.Client, obj client.Object) []reconcile.Request {
	peer, ok := obj.(*bgpv1alpha1.BGPPeer)
	if !ok {
		return nil
	}
	return enqueueRoutersForTarget(ctx, c, peer.Namespace,
		peer.Spec.RouterRef, peer.Spec.RouterSelector,
		"BGPPeer/"+peer.Name,
	)
}
