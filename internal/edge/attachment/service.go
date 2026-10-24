// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"context"
	"fmt"
	"strings"
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
	"go.datum.net/galactic/internal/edge/diag"
	"go.datum.net/galactic/internal/trafficpolicy/cell"
)

// EdgeService condition types. Admitted reports whether the grant can admit
// attachments, and TrafficPolicyResolved whether both directions of its
// traffic policy resolve to a policy its attachments enforce.
const (
	ConditionServiceAdmitted      = "Admitted"
	ConditionServiceTrafficPolicy = "TrafficPolicyResolved"
)

// ServiceReconciler reports on each EdgeService whether it can admit
// attachments: its provider is registered and approved, its VPC exists with
// the granted UID and a fabric identifier, its client pool lies inside the
// VPC and overlaps no earlier service's, and it has not expired. Attachments
// are decided independently by Reconciler; this condition explains them. It
// also reports whether the service's traffic policy references resolve.
type ServiceReconciler struct {
	Client    client.Client
	APIReader client.Reader
	// MaxSkew is the cell's maximum wall-clock error, as Reconciler's.
	MaxSkew time.Duration
	// Now is the wall clock. Nil means time.Now.
	Now func() time.Time
	// Diag records the service entering a refused or unresolved state.
	Diag *diag.Recorder
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
	policy, err := r.trafficPolicy(ctx, &svc)
	if err != nil {
		return ctrl.Result{}, err
	}
	changed := svc.Status.ObservedGeneration != svc.Generation
	var entered []metav1.Condition
	for _, cond := range []metav1.Condition{cond, policy} {
		// A transient refusal shares its reason with a definite one, so a new
		// message also counts as a new failure.
		prev := meta.FindStatusCondition(svc.Status.Conditions, cond.Type)
		if cond.Status == metav1.ConditionFalse &&
			(diag.EnteredFailure(svc.Status.Conditions, cond.Type, cond.Reason) || prev.Message != cond.Message) {
			entered = append(entered, cond)
		}
		c := meta.FindStatusCondition(svc.Status.Conditions, cond.Type)
		changed = changed || c == nil || c.Status != cond.Status || c.Reason != cond.Reason ||
			c.Message != cond.Message || c.ObservedGeneration != cond.ObservedGeneration
	}
	if changed {
		before := svc.DeepCopy()
		svc.Status.ObservedGeneration = svc.Generation
		meta.SetStatusCondition(&svc.Status.Conditions, cond)
		meta.SetStatusCondition(&svc.Status.Conditions, policy)
		if err := r.Client.Status().Patch(ctx, &svc,
			client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, fmt.Errorf("update EdgeService %s status: %w", req.NamespacedName, err)
		}
	}
	corr := diag.Correlation{Provider: svc.Spec.ProviderRef.Name, Service: svc.Namespace + "/" + svc.Name,
		ServiceUID: string(svc.UID), ServiceGeneration: svc.Generation}
	for _, c := range entered {
		stage := diag.StageAdmission
		if c.Type == ConditionServiceTrafficPolicy {
			stage = diag.StagePolicy
		}
		if c.Type == ConditionServiceAdmitted && ref != nil && ref.transient {
			continue
		}
		r.Diag.Failure(&svc, stage, c.Reason, c.Message, corr)
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

// trafficPolicy is the service's TrafficPolicyResolved condition: true when
// each direction resolves to the built-in default or a valid policy in the
// service's namespace, false with the first direction that does not. A
// service whose directions both take the built-in default reports reason
// Default, since its attachments carry no traffic.
func (r *ServiceReconciler) trafficPolicy(ctx context.Context, svc *galacticv1alpha1.EdgeService,
) (metav1.Condition, error) {
	var spec galacticv1alpha1.TrafficPolicyBindingSpec
	if svc.Spec.TrafficPolicy != nil {
		spec = *svc.Spec.TrafficPolicy
	}
	out := metav1.Condition{
		Type: ConditionServiceTrafficPolicy, Status: metav1.ConditionTrue, Reason: cell.ReasonResolved,
		ObservedGeneration: svc.Generation,
	}
	var messages []string
	defaults := 0
	for _, d := range []struct {
		name string
		ref  *galacticv1alpha1.LocalPolicyReference
	}{{"ingress", spec.IngressPolicyRef}, {"egress", spec.EgressPolicyRef}} {
		var policy *galacticv1alpha1.TrafficPolicy
		if d.ref != nil {
			var p galacticv1alpha1.TrafficPolicy
			switch err := r.Client.Get(ctx, client.ObjectKey{Namespace: svc.Namespace, Name: d.ref.Name}, &p); {
			case err == nil:
				policy = &p
			case !apierrors.IsNotFound(err):
				return out, fmt.Errorf("get TrafficPolicy %s/%s: %w", svc.Namespace, d.ref.Name, err)
			}
		}
		st := cell.Resolve(d.ref, policy, svc.Generation)
		c := meta.FindStatusCondition(st.Conditions, cell.ConditionResolved)
		messages = append(messages, d.name+": "+c.Message)
		if c.Reason == cell.ReasonDefault {
			defaults++
		}
		if c.Status != metav1.ConditionTrue && out.Status == metav1.ConditionTrue {
			out.Status, out.Reason = metav1.ConditionFalse, c.Reason
		}
	}
	if defaults == 2 {
		out.Reason = cell.ReasonDefault
	}
	out.Message = strings.Join(messages, "; ")
	return out, nil
}

// SetupWithManager registers the reconciler. A service is reconciled when it,
// its VPC, its provider, a TrafficPolicy it references or another service in
// its namespace changes, since another service's pool decides whether this
// one's conflicts.
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
		Watches(&galacticv1alpha1.TrafficPolicy{}, services(func(s *galacticv1alpha1.EdgeService, o client.Object) bool {
			p := s.Spec.TrafficPolicy
			return p != nil && ((p.IngressPolicyRef != nil && p.IngressPolicyRef.Name == o.GetName()) ||
				(p.EgressPolicyRef != nil && p.EgressPolicyRef.Name == o.GetName()))
		})).
		Complete(r)
}
