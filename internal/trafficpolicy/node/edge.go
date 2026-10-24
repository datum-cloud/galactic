// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// Field indexes of the EdgeAttachment controller: attachments by their
// service's UID, and services by every policy name they reference.
const (
	edgeServiceIndex = "galactic.datumapis.com/node-edge-service-uid"
	edgePolicyIndex  = "galactic.datumapis.com/node-edge-policy-refs"
)

// setupEdge registers the EdgeAttachment controller. An attachment is
// reconciled when it, its EdgeService or a TrafficPolicy its service
// references changes.
func (r *Reconciler) setupEdge(mgr ctrl.Manager) error {
	indexer := mgr.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &galacticv1alpha1.EdgeAttachment{}, edgeServiceIndex,
		func(o client.Object) []string {
			return []string{o.(*galacticv1alpha1.EdgeAttachment).Spec.ServiceRef.UID}
		}); err != nil {
		return fmt.Errorf("index edge attachments by service: %w", err)
	}
	if err := indexer.IndexField(context.Background(), &galacticv1alpha1.EdgeService{}, edgePolicyIndex,
		func(o client.Object) []string {
			return edgePolicyRefs(o.(*galacticv1alpha1.EdgeService))
		}); err != nil {
		return fmt.Errorf("index edge services by policy: %w", err)
	}
	c := mgr.GetClient()
	attachments := func(ctx context.Context, services []galacticv1alpha1.EdgeService) []reconcile.Request {
		var out []reconcile.Request
		for i := range services {
			var list galacticv1alpha1.EdgeAttachmentList
			if err := c.List(ctx, &list, client.MatchingFields{edgeServiceIndex: string(services[i].UID)}); err != nil {
				ctrl.LoggerFrom(ctx).Error(err, "list edge attachments of service", "service", services[i].Name)
				continue
			}
			for j := range list.Items {
				if list.Items[j].Status.NodeName == r.NodeName {
					out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[j])})
				}
			}
		}
		return out
	}
	byService := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		svc, ok := o.(*galacticv1alpha1.EdgeService)
		if !ok {
			return nil
		}
		return attachments(ctx, []galacticv1alpha1.EdgeService{*svc})
	})
	byPolicy := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		var services galacticv1alpha1.EdgeServiceList
		if err := c.List(ctx, &services, client.InNamespace(o.GetNamespace()),
			client.MatchingFields{edgePolicyIndex: o.GetName()}); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "list edge services referencing policy", "policy", o.GetName())
			return nil
		}
		return attachments(ctx, services.Items)
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("traffic-policy-edge").
		For(&galacticv1alpha1.EdgeAttachment{}).
		Watches(&galacticv1alpha1.EdgeService{}, byService).
		Watches(&galacticv1alpha1.TrafficPolicy{}, byPolicy).
		Complete(reconcile.Func(r.ReconcileEdge))
}

func edgePolicyRefs(s *galacticv1alpha1.EdgeService) []string {
	if s.Spec.TrafficPolicy == nil {
		return nil
	}
	var refs []string
	for _, d := range directions {
		if ref := d.ref(s.Spec.TrafficPolicy); ref != nil {
			refs = append(refs, ref.Name)
		}
	}
	return refs
}

// ReconcileEdge is the EdgeAttachment controller's reconcile. It enforces, on
// the host link of an EdgeAttachment on this node,
// the policy its EdgeService selects for each direction, resolved in the
// service's namespace and never the attachment's, which its provider
// controls. An attachment core has not admitted, or whose service is gone,
// being deleted, replaced or granting another provider, gets no snapshot, so
// its link denies everything. galactic-edge writes the link's policy row
// before the link comes up; until then the link carries nothing and this
// retries. No status is written: the counters report what each direction
// does.
func (r *Reconciler) ReconcileEdge(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.open(ctx); err != nil {
		log.Info("traffic policy maps are not available yet", "error", err.Error())
		return ctrl.Result{RequeueAfter: pendingRetry}, nil
	}
	r.sweepAdopted(ctx)
	r.sweepPins(ctx)

	key := subject{edge: true, NamespacedName: req.NamespacedName}
	var att galacticv1alpha1.EdgeAttachment
	if err := r.Client.Get(ctx, req.NamespacedName, &att); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		r.forget(ctx, key)
		return ctrl.Result{}, nil
	}
	if att.Status.NodeName != r.NodeName || att.Status.HostLink == "" {
		r.forget(ctx, key)
		return ctrl.Result{}, nil
	}
	ifindex, row, pending, err := r.interfaceRow(ctx, key, att.Status.HostLink)
	if err != nil {
		return ctrl.Result{}, err
	}
	if pending != "" {
		return ctrl.Result{RequeueAfter: pendingRetry}, nil
	}
	svc, refused, err := r.edgeService(ctx, &att)
	if err != nil {
		return ctrl.Result{}, err
	}
	labels := interfaceLabels{
		namespace: att.Namespace, attachment: att.Name, iface: att.Status.HostLink, ifaceUID: string(att.UID),
	}
	if svc != nil {
		labels.vpc = svc.Spec.VPCRef.Name
	}
	r.ifaces[key] = iface{ifindex: ifindex, token: row.PolicyToken, labels: labels}
	if refused != "" {
		// A grant that could not be withdrawn is retried at once, not at
		// the next resync.
		log.V(1).Info("enforcing no traffic policy on edge attachment", "reason", refused)
		return ctrl.Result{RequeueAfter: resync}, r.drop(ctx, ifindex, key)
	}

	var errs []error
	for _, d := range directions {
		var ref *galacticv1alpha1.LocalPolicyReference
		if svc.Spec.TrafficPolicy != nil {
			ref = d.ref(svc.Spec.TrafficPolicy)
		}
		res, err := r.reconcileDirection(ctx, bindingKey{ifindex, d.dir}, key, labels, row.PolicyToken,
			svc.Namespace, ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.name, err))
		} else if res.State != galacticv1alpha1.StateApplied {
			log.V(1).Info("edge attachment direction not applied", "direction", d.name, "state", res.State,
				"message", res.Message)
		}
	}
	return ctrl.Result{RequeueAfter: resync}, errors.Join(errs...)
}

// edgeService returns the service whose policy att enforces, or why it
// enforces none.
func (r *Reconciler) edgeService(ctx context.Context, att *galacticv1alpha1.EdgeAttachment) (
	*galacticv1alpha1.EdgeService, string, error,
) {
	if !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted) {
		return nil, "the attachment is not admitted", nil
	}
	ref := att.Spec.ServiceRef
	var svc galacticv1alpha1.EdgeService
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, "EdgeService " + ref.Namespace + "/" + ref.Name + " does not exist", nil
		}
		return nil, "", err
	}
	switch {
	case string(svc.UID) != ref.UID:
		return nil, "EdgeService " + ref.Namespace + "/" + ref.Name + " was replaced", nil
	case !svc.DeletionTimestamp.IsZero():
		return nil, "EdgeService " + ref.Namespace + "/" + ref.Name + " is being deleted", nil
	case svc.Spec.ProviderRef != att.Spec.ProviderRef:
		return nil, "EdgeService " + ref.Namespace + "/" + ref.Name + " grants another provider", nil
	}
	return &svc, "", nil
}
