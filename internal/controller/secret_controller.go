// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// SecretReconciler watches Secrets and enqueues BGPRouter(s) that reference
// them via BGPPeer.spec.authSecretRef.
type SecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile enqueues affected BGPRouter(s) when a referenced Secret changes.
func (r *SecretReconciler) Reconcile(_ context.Context, _ ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

// SetupWithManager registers the SecretReconciler with the manager.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Named("secret").
		Complete(r)
}

// secretToRouterRequests maps a Secret to reconcile.Requests for BGPRouter(s)
// that reference it via BGPPeer.spec.authSecretRef.
func secretToRouterRequests(ctx context.Context, c client.Client, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)

	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}

	// Find BGPPeers that reference this secret.
	peerList := &bgpv1alpha1.BGPPeerList{}
	if err := c.List(ctx, peerList,
		client.InNamespace(secret.Namespace),
		client.MatchingFields{BGPPeerBySecretName: secret.Name},
	); err != nil {
		logger.Error(err, "list BGPPeers by secret name", "secret", secret.Name)
		return nil
	}

	// Expand each peer to its router(s).
	seen := make(map[types.NamespacedName]bool)
	var reqs []reconcile.Request
	for i := range peerList.Items {
		peer := &peerList.Items[i]
		for _, req := range peerToRouterRequests(ctx, c, peer) {
			if !seen[req.NamespacedName] {
				seen[req.NamespacedName] = true
				reqs = append(reqs, req)
			}
		}
	}
	return reqs
}
