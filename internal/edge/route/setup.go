// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"fmt"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
)

// Field indexes on EdgeRoute, mapping each input's events back to the routes
// it decides.
const (
	indexVPC        = "spec.vpcUID"
	indexProvider   = "spec.providerRef.name"
	indexInstance   = "edge.instance"
	indexAttachment = "edge.attachment"
)

// InstanceLeases admits only instance leases: Leases carrying
// EdgeLeaseProviderLabel.
var InstanceLeases = predicate.NewPredicateFuncs(func(o client.Object) bool {
	_, ok := o.GetLabels()[galacticv1alpha1.EdgeLeaseProviderLabel]
	return ok
})

// LeaseCache limits a manager's Lease cache to instance leases, so it does not
// hold every Lease in the cluster. Pass it in the manager's cache options
// whenever the manager watches leases.
func LeaseCache() map[client.Object]cache.ByObject {
	req, err := labels.NewRequirement(galacticv1alpha1.EdgeLeaseProviderLabel, selection.Exists, nil)
	if err != nil {
		panic(err)
	}
	return map[client.Object]cache.ByObject{&coordinationv1.Lease{}: {Label: labels.NewSelector().Add(*req)}}
}

// Setup registers the route reconciler, the index reconciler and the
// instance reaper with mgr. They run on the leader only, and share Params
// and Clock.
func Setup(mgr ctrl.Manager, params claim.Params, clock claim.Clock) error {
	if err := params.Validate(); err != nil {
		return err
	}
	c, reader := mgr.GetClient(), mgr.GetAPIReader()
	if err := (&InstanceReaper{Client: c, APIReader: reader, Params: params, Clock: clock}).setup(mgr); err != nil {
		return fmt.Errorf("set up EdgeInstance reaper: %w", err)
	}
	if err := (&IndexReconciler{Client: c, APIReader: reader, Params: params, Clock: clock}).setup(mgr); err != nil {
		return fmt.Errorf("set up EdgeRouteIndex reconciler: %w", err)
	}
	if err := (&Reconciler{Client: c, APIReader: reader, Params: params, Clock: clock}).setup(mgr); err != nil {
		return fmt.Errorf("set up EdgeRoute reconciler: %w", err)
	}
	return nil
}

func (r *Reconciler) setup(mgr ctrl.Manager) error {
	ctx := context.Background()
	indexer := mgr.GetFieldIndexer()
	for field, extract := range map[string]func(*galacticv1alpha1.EdgeRoute) []string{
		indexVPC:      func(rt *galacticv1alpha1.EdgeRoute) []string { return []string{rt.Spec.VPCUID} },
		indexProvider: func(rt *galacticv1alpha1.EdgeRoute) []string { return []string{rt.Spec.ProviderRef.Name} },
		indexInstance: func(rt *galacticv1alpha1.EdgeRoute) []string {
			var out []string
			if c := rt.Spec.Claim; c != nil {
				out = append(out, c.HolderInstance)
			}
			if a := rt.Status.Accepted; a != nil {
				out = append(out, a.Instance)
			}
			return out
		},
		indexAttachment: func(rt *galacticv1alpha1.EdgeRoute) []string {
			var out []string
			if c := rt.Spec.Claim; c != nil {
				out = append(out, c.Attachment)
			}
			if a := rt.Status.Accepted; a != nil {
				out = append(out, a.Attachment)
			}
			return out
		},
	} {
		if err := indexer.IndexField(ctx, &galacticv1alpha1.EdgeRoute{}, field, func(o client.Object) []string {
			rt, ok := o.(*galacticv1alpha1.EdgeRoute)
			if !ok {
				return nil
			}
			return extract(rt)
		}); err != nil {
			return fmt.Errorf("index EdgeRoute %s: %w", field, err)
		}
	}
	c := mgr.GetClient()
	byField := func(field string, value func(client.Object) string, namespaced bool) handler.EventHandler {
		return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
			v := value(o)
			if v == "" {
				return nil
			}
			opts := []client.ListOption{client.MatchingFields{field: v}}
			if namespaced {
				opts = append(opts, client.InNamespace(o.GetNamespace()))
			}
			var list galacticv1alpha1.EdgeRouteList
			if err := c.List(ctx, &list, opts...); err != nil {
				return nil
			}
			out := make([]reconcile.Request, 0, len(list.Items))
			for i := range list.Items {
				out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
			}
			return out
		})
	}
	name := func(o client.Object) string { return o.GetName() }
	return ctrl.NewControllerManagedBy(mgr).
		Named("edge-route").
		For(&galacticv1alpha1.EdgeRoute{}).
		Watches(&galacticv1alpha1.EdgeInstance{}, byField(indexInstance, name, true)).
		// A lease has its instance's namespace and name; its renewals and
		// releases decide pending takeovers.
		Watches(&coordinationv1.Lease{}, byField(indexInstance, name, true), builder.WithPredicates(InstanceLeases)).
		Watches(&galacticv1alpha1.EdgeAttachment{}, byField(indexAttachment, name, true)).
		Watches(&galacticv1alpha1.EdgeService{}, byField(indexVPC, func(o client.Object) string {
			if s, ok := o.(*galacticv1alpha1.EdgeService); ok {
				return s.Spec.VPCRef.UID
			}
			return ""
		}, false)).
		Watches(&galacticv1alpha1.EdgeProvider{}, byField(indexProvider, name, false)).
		Watches(&galacticv1alpha1.EdgeRouteIndex{}, byField(indexVPC, func(o client.Object) string {
			if idx, ok := o.(*galacticv1alpha1.EdgeRouteIndex); ok {
				return idx.Spec.VPCUID
			}
			return ""
		}, false)).
		Complete(r)
}

func (r *IndexReconciler) setup(mgr ctrl.Manager) error {
	// A route's deletion or revocation reaches the index its accepted
	// holder is committed to.
	toIndex := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		rt, ok := o.(*galacticv1alpha1.EdgeRoute)
		if !ok || rt.Status.Accepted == nil {
			return nil
		}
		return []reconcile.Request{{NamespacedName: client.ObjectKey{
			Namespace: rt.Status.Accepted.VPCNamespace, Name: rt.Spec.VPCUID,
		}}}
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("edge-route-index").
		For(&galacticv1alpha1.EdgeRouteIndex{}).
		Watches(&galacticv1alpha1.EdgeRoute{}, toIndex).
		Complete(r)
}

func (r *InstanceReaper) setup(mgr ctrl.Manager) error {
	c := mgr.GetClient()
	// A pod's deletion or replacement reaches the instances that name it.
	toInstances := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		var list galacticv1alpha1.EdgeInstanceList
		if err := c.List(ctx, &list, client.InNamespace(o.GetNamespace())); err != nil {
			return nil
		}
		var out []reconcile.Request
		for i := range list.Items {
			if list.Items[i].Spec.PodName == o.GetName() {
				out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
			}
		}
		return out
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("edge-instance-reaper").
		For(&galacticv1alpha1.EdgeInstance{}).
		Watches(&corev1.Pod{}, toInstances).
		Complete(r)
}
