// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// EndpointReconciler reports, on every FabricEndpoint of a namespace,
// whether topologies may peer over it. Conflicts depend on every other
// endpoint of the namespace, so one pass covers the whole namespace.
type EndpointReconciler struct {
	client.Client
	// Namespace is the only namespace whose endpoints are served; empty
	// serves every namespace.
	Namespace string
}

// Reconcile updates the status of every endpoint in req's namespace.
func (r *EndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if r.Namespace != "" && req.Namespace != r.Namespace {
		return ctrl.Result{}, nil
	}
	ns := client.InNamespace(req.Namespace)
	endpoints := &networkv1alpha1.FabricEndpointList{}
	if err := r.List(ctx, endpoints, ns); err != nil {
		return ctrl.Result{}, err
	}
	if len(endpoints.Items) == 0 {
		return ctrl.Result{}, nil
	}
	routerList := &networkv1alpha1.BGPRouterList{}
	if err := r.List(ctx, routerList, ns); err != nil {
		return ctrl.Result{}, err
	}
	routers := make(map[string]*networkv1alpha1.BGPRouter, len(routerList.Items))
	for i := range routerList.Items {
		routers[routerList.Items[i].Name] = &routerList.Items[i]
	}
	cells, err := localCells(ctx, r.Client, req.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	for _, s := range Analyze(endpoints.Items, cells, routers) {
		if err := r.writeStatus(ctx, s); client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *EndpointReconciler) writeStatus(ctx context.Context, s *EndpointState) error {
	ep := s.Endpoint
	before := ep.DeepCopy()
	gen := ep.Generation
	ready := metav1.Condition{Type: networkv1alpha1.FabricEndpointConditionReady, Status: metav1.ConditionTrue,
		Reason: s.ReadyReason, Message: s.ReadyMessage, ObservedGeneration: gen}
	if !s.Usable {
		ready.Status = metav1.ConditionFalse
	}
	conflict := metav1.Condition{Type: networkv1alpha1.FabricEndpointConditionConflict, Status: metav1.ConditionFalse,
		Reason:             networkv1alpha1.FabricEndpointReasonNoConflict,
		Message:            "no other endpoint claims this one's identity or addresses",
		ObservedGeneration: gen}
	if s.ConflictReason != "" {
		conflict.Status, conflict.Reason, conflict.Message = metav1.ConditionTrue, s.ConflictReason, s.ConflictMessage
	}
	meta.SetStatusCondition(&ep.Status.Conditions, ready)
	meta.SetStatusCondition(&ep.Status.Conditions, conflict)
	ep.Status.ObservedGeneration = gen
	ep.Status.Local = s.Local
	if equality.Semantic.DeepEqual(before.Status, ep.Status) {
		return nil
	}
	return r.Status().Patch(ctx, ep, client.MergeFrom(before))
}

// SetupWithManager reconciles a namespace's endpoints when any endpoint,
// router or topology in it changes.
func (r *EndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	byNamespace := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: "endpoints"}}}
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("fabric-endpoints").
		Watches(&networkv1alpha1.FabricEndpoint{}, byNamespace).
		Watches(&networkv1alpha1.BGPRouter{}, byNamespace).
		Watches(&networkv1alpha1.FabricTopology{}, byNamespace).
		Complete(r)
}
