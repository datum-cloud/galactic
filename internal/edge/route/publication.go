// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// PublicationReconciler reports on each EdgeAttachment whether any route
// accepted on it is published (EdgeAttachmentPublished). It only reports:
// what is advertised is decided per route by Reconciler and, on the node, by
// galactic-router's gate check.
type PublicationReconciler struct {
	Client client.Client
}

// Reconcile implements reconcile.Reconciler for EdgeAttachments.
func (r *PublicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var att galacticv1alpha1.EdgeAttachment
	if err := r.Client.Get(ctx, req.NamespacedName, &att); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !att.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	var routes galacticv1alpha1.EdgeRouteList
	if err := r.Client.List(ctx, &routes, client.InNamespace(att.Namespace)); err != nil {
		return ctrl.Result{}, err
	}
	published := 0
	for i := range routes.Items {
		rt := &routes.Items[i]
		if a := rt.Status.Accepted; a != nil && a.AttachmentUID == string(att.UID) &&
			meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRoutePublished) {
			published++
		}
	}
	cond := metav1.Condition{Type: galacticv1alpha1.EdgeAttachmentPublished, Status: metav1.ConditionFalse,
		Reason: ReasonNoRoutesPublished, Message: "no route accepted on the attachment is published",
		ObservedGeneration: att.Generation}
	if published > 0 {
		cond.Status, cond.Reason = metav1.ConditionTrue, ReasonRoutesPublished
		cond.Message = fmt.Sprintf("%d accepted routes published", published)
	}
	if c := meta.FindStatusCondition(att.Status.Conditions, cond.Type); c != nil && c.Status == cond.Status &&
		c.Reason == cond.Reason && c.Message == cond.Message {
		return ctrl.Result{}, nil
	}
	before := att.DeepCopy()
	meta.SetStatusCondition(&att.Status.Conditions, cond)
	if err := r.Client.Status().Patch(ctx, &att,
		client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		return ctrl.Result{}, fmt.Errorf("update EdgeAttachment %s Published: %w", req.NamespacedName, err)
	}
	return ctrl.Result{}, nil
}

func (r *PublicationReconciler) setup(mgr ctrl.Manager) error {
	// A route's change reaches the attachments its old and new versions
	// name, so the attachment a route moved away from is decided too.
	toAttachments := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		rt, ok := o.(*galacticv1alpha1.EdgeRoute)
		if !ok {
			return nil
		}
		var out []reconcile.Request
		if a := rt.Status.Accepted; a != nil {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKey{Namespace: rt.Namespace, Name: a.Attachment}})
		}
		if c := rt.Spec.Claim; c != nil {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKey{Namespace: rt.Namespace, Name: c.Attachment}})
		}
		return out
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("edge-attachment-publication").
		For(&galacticv1alpha1.EdgeAttachment{}).
		Watches(&galacticv1alpha1.EdgeRoute{}, toAttachments).
		Complete(r)
}
