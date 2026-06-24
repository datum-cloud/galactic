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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// NodeReconciler watches Node resources for IPv6 address changes and enqueues
// any BGPRouter targeting that node.
type NodeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile enqueues BGPRouter(s) when the watched Node changes.
func (r *NodeReconciler) Reconcile(_ context.Context, _ ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

// SetupWithManager registers the NodeReconciler with the manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []reconcile.Request {
				return nodeToRouterRequests(ctx, r.Client, obj)
			},
		)).
		Named("node").
		Complete(r)
}

// nodeToRouterRequests maps a Node to reconcile.Requests for BGPRouters that
// target it via spec.targetRef.name.
func nodeToRouterRequests(ctx context.Context, c client.Client, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)

	node, ok := obj.(*corev1.Node)
	if !ok {
		return nil
	}

	routerList := &bgpv1alpha1.BGPRouterList{}
	if err := c.List(ctx, routerList,
		client.MatchingFields{BGPRouterByTargetName: node.Name},
	); err != nil {
		logger.Error(err, "list BGPRouters for node change", "node", node.Name)
		return nil
	}

	reqs := make([]reconcile.Request, 0, len(routerList.Items))
	for _, router := range routerList.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: router.Namespace,
				Name:      router.Name,
			},
		})
	}
	return reqs
}
