// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
)

// Field indexes on EdgeAttachment, mapping each input's events back to the
// attachments it decides.
const (
	indexServiceUID = "spec.serviceRef.uid"
	indexPodUID     = "spec.podUID"
	indexNodeName   = "status.nodeName"
	indexInstance   = "spec.instanceRef.name"
)

// Setup registers the attachment reconciler, the admission sources that
// feed its Authority, the EdgeService status reconciler and the provider
// binding reconciler with mgr. All of them run on the leader; a new leader
// reloads the Authority from its informers before it decides anything, and
// any decision the Authority has not caught up with is retried.
func Setup(mgr ctrl.Manager, r *Reconciler) error {
	providers := &admission.ProviderSource{Reader: mgr.GetClient(), Authority: r.Authority}
	if err := providers.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up EdgeProvider source: %w", err)
	}
	grants := &admission.GrantSource{Reader: mgr.GetClient(), Authority: r.Authority}
	if err := grants.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up EdgeService source: %w", err)
	}
	if err := (&ServiceReconciler{
		Client: mgr.GetClient(), APIReader: r.APIReader, MaxSkew: r.MaxSkew, Now: r.Now, Diag: r.Diag,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up EdgeService reconciler: %w", err)
	}
	if err := (&ProviderBindingReconciler{}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up EdgeProvider binding reconciler: %w", err)
	}
	return r.SetupWithManager(mgr)
}

// SetupWithManager registers the reconciler, its field indexes and its
// watches.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	indexer := mgr.GetFieldIndexer()
	for field, extract := range map[string]func(*galacticv1alpha1.EdgeAttachment) string{
		indexServiceUID: func(a *galacticv1alpha1.EdgeAttachment) string { return a.Spec.ServiceRef.UID },
		indexPodUID:     func(a *galacticv1alpha1.EdgeAttachment) string { return a.Spec.PodUID },
		indexNodeName:   func(a *galacticv1alpha1.EdgeAttachment) string { return a.Status.NodeName },
		indexInstance:   func(a *galacticv1alpha1.EdgeAttachment) string { return a.Spec.InstanceRef.Name },
	} {
		if err := indexer.IndexField(ctx, &galacticv1alpha1.EdgeAttachment{}, field, func(o client.Object) []string {
			a, ok := o.(*galacticv1alpha1.EdgeAttachment)
			if !ok || extract(a) == "" {
				return nil
			}
			return []string{extract(a)}
		}); err != nil {
			return fmt.Errorf("index EdgeAttachment %s: %w", field, err)
		}
	}
	stopped := make(chan struct{})
	r.stopped = stopped
	r.ended = make(chan event.GenericEvent)
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		<-ctx.Done()
		close(stopped)
		return nil
	})); err != nil {
		return err
	}

	c := mgr.GetClient()
	byField := func(field string, value func(client.Object) string, opts ...client.ListOption) handler.EventHandler {
		return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
			v := value(o)
			if v == "" {
				return nil
			}
			var list galacticv1alpha1.EdgeAttachmentList
			if err := c.List(ctx, &list, append(opts, client.MatchingFields{field: v})...); err != nil {
				return nil
			}
			return requests(list.Items)
		})
	}
	uid := func(o client.Object) string { return string(o.GetUID()) }
	// A VPC or provider change reaches attachments through the services
	// that grant it.
	viaServices := func(match func(*galacticv1alpha1.EdgeService, client.Object) bool) handler.EventHandler {
		return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
			var services galacticv1alpha1.EdgeServiceList
			var opts []client.ListOption
			if o.GetNamespace() != "" {
				opts = append(opts, client.InNamespace(o.GetNamespace()))
			}
			if err := c.List(ctx, &services, opts...); err != nil {
				return nil
			}
			var out []reconcile.Request
			for i := range services.Items {
				if !match(&services.Items[i], o) {
					continue
				}
				var list galacticv1alpha1.EdgeAttachmentList
				if err := c.List(ctx, &list, client.MatchingFields{indexServiceUID: string(services.Items[i].UID)}); err == nil {
					out = append(out, requests(list.Items)...)
				}
			}
			return out
		})
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("edge-attachment").
		For(&galacticv1alpha1.EdgeAttachment{}).
		Watches(&galacticv1alpha1.EdgeService{}, byField(indexServiceUID, uid)).
		// Granted prefixes are exclusive in a VPC, so a change to one
		// service's grant decides the other services' there.
		Watches(&galacticv1alpha1.EdgeService{}, viaServices(func(s *galacticv1alpha1.EdgeService, o client.Object) bool {
			other, ok := o.(*galacticv1alpha1.EdgeService)
			return ok && s.UID != other.UID && s.Spec.VPCRef.UID == other.Spec.VPCRef.UID
		}), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&galacticv1alpha1.EdgeInstance{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, o client.Object) []reconcile.Request {
				var list galacticv1alpha1.EdgeAttachmentList
				if err := c.List(ctx, &list, client.InNamespace(o.GetNamespace()),
					client.MatchingFields{indexInstance: o.GetName()}); err != nil {
					return nil
				}
				return requests(list.Items)
			})).
		Watches(&corev1.Pod{}, byField(indexPodUID, uid)).
		Watches(&corev1.Node{}, byField(indexNodeName, func(o client.Object) string { return o.GetName() })).
		Watches(&cloudv1alpha1.VPC{}, viaServices(func(s *galacticv1alpha1.EdgeService, o client.Object) bool {
			return s.Spec.VPCRef.Name == o.GetName()
		})).
		Watches(&galacticv1alpha1.EdgeProvider{}, viaServices(func(s *galacticv1alpha1.EdgeService, o client.Object) bool {
			return s.Spec.ProviderRef.Name == o.GetName()
		})).
		WatchesRawSource(source.Channel(r.ended, &handler.EnqueueRequestForObject{})).
		Complete(r)
}

func requests(items []galacticv1alpha1.EdgeAttachment) []reconcile.Request {
	out := make([]reconcile.Request, 0, len(items))
	for i := range items {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&items[i])})
	}
	return out
}
