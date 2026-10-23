// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
)

// ConditionServiceAdmitted is the EdgeService condition reporting whether
// the grant can admit attachments.
const ConditionServiceAdmitted = "Admitted"

// ServiceReconciler reports on each EdgeService whether it can admit
// attachments: its provider is registered and approved, its VPC exists with
// the granted UID and a fabric identifier, its client pool lies inside the
// VPC and overlaps no earlier service's, and it has not expired. Attachments
// are decided independently by Reconciler; this condition explains them.
type ServiceReconciler struct {
	Client    client.Client
	APIReader client.Reader
	// MaxSkew is the cell's maximum wall-clock error, as Reconciler's.
	MaxSkew time.Duration
	// Now is the wall clock. Nil means time.Now.
	Now func() time.Time
}

// Reconcile implements reconcile.Reconciler.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var svc galacticv1alpha1.EdgeService
	if err := r.APIReader.Get(ctx, req.NamespacedName, &svc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !svc.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	ref, err := r.check(ctx, &svc, now)
	if err != nil {
		return ctrl.Result{}, err
	}
	cond := metav1.Condition{
		Type: ConditionServiceAdmitted, Status: metav1.ConditionTrue, Reason: ReasonAdmitted,
		ObservedGeneration: svc.Generation,
		Message:            "provider approved; grant, VPC and client pool valid",
	}
	if ref != nil {
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, ref.reason, ref.message
	}
	if c := meta.FindStatusCondition(svc.Status.Conditions, cond.Type); c == nil || c.Status != cond.Status ||
		c.Reason != cond.Reason || c.Message != cond.Message || c.ObservedGeneration != cond.ObservedGeneration ||
		svc.Status.ObservedGeneration != svc.Generation {
		before := svc.DeepCopy()
		svc.Status.ObservedGeneration = svc.Generation
		meta.SetStatusCondition(&svc.Status.Conditions, cond)
		if err := r.Client.Status().Patch(ctx, &svc,
			client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, fmt.Errorf("update EdgeService %s status: %w", req.NamespacedName, err)
		}
	}
	switch {
	case ref != nil && ref.transient:
		return ctrl.Result{RequeueAfter: transientRetry}, nil
	case ref == nil && svc.Spec.ValidUntil != nil:
		return ctrl.Result{RequeueAfter: svc.Spec.ValidUntil.Add(-r.MaxSkew).Sub(now)}, nil
	}
	return ctrl.Result{}, nil
}

// check returns why svc cannot admit attachments, or nil.
func (r *ServiceReconciler) check(ctx context.Context, svc *galacticv1alpha1.EdgeService, now time.Time,
) (*refusal, error) {
	var provider galacticv1alpha1.EdgeProvider
	switch err := r.APIReader.Get(ctx, client.ObjectKey{Name: svc.Spec.ProviderRef.Name}, &provider); {
	case apierrors.IsNotFound(err):
		return refuse(string(admission.UnknownProvider), "provider %q is not registered", svc.Spec.ProviderRef.Name), nil
	case err != nil:
		return nil, err
	case !provider.Status.Approved || !provider.DeletionTimestamp.IsZero():
		return refuse(string(admission.ProviderNotApproved), "provider %q is not approved", provider.Name), nil
	}
	if _, err := admission.GrantFromAPI(svc); err != nil {
		return refuse(string(admission.InvalidRequest), "%v", err), nil
	}
	if v := svc.Spec.ValidUntil; v != nil && !now.Before(v.Add(-r.MaxSkew)) {
		return refuse(string(admission.GrantExpired), "grant expired at %s", v.UTC().Format(time.RFC3339)), nil
	}
	_, ref, err := checkVPC(ctx, r.APIReader, svc)
	return ref, err
}

// SetupWithManager registers the reconciler. A service is reconciled when it,
// its VPC, its provider or another service in its namespace changes, since
// another service's pool decides whether this one's conflicts.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	c := mgr.GetClient()
	services := func(match func(*galacticv1alpha1.EdgeService, client.Object) bool) handler.EventHandler {
		return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
			var list galacticv1alpha1.EdgeServiceList
			var opts []client.ListOption
			if o.GetNamespace() != "" {
				opts = append(opts, client.InNamespace(o.GetNamespace()))
			}
			if err := c.List(ctx, &list, opts...); err != nil {
				return nil
			}
			var out []reconcile.Request
			for i := range list.Items {
				if match(&list.Items[i], o) {
					out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
				}
			}
			return out
		})
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("edge-service").
		For(&galacticv1alpha1.EdgeService{}).
		Watches(&galacticv1alpha1.EdgeService{}, services(func(*galacticv1alpha1.EdgeService, client.Object) bool {
			return true
		}), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&cloudv1alpha1.VPC{}, services(func(s *galacticv1alpha1.EdgeService, o client.Object) bool {
			return s.Spec.VPCRef.Name == o.GetName()
		})).
		Watches(&galacticv1alpha1.EdgeProvider{}, services(func(s *galacticv1alpha1.EdgeService, o client.Object) bool {
			return s.Spec.ProviderRef.Name == o.GetName()
		})).
		Complete(r)
}
