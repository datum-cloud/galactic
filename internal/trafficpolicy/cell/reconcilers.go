// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cell

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/trafficpolicy"
	"go.datum.net/galactic/internal/trafficpolicy/webhook"
)

// FieldOwner is the server-side apply field manager for everything
// galactic-controller writes.
const FieldOwner = "galactic-controller"

// policyRefIndex indexes bindings by every policy name they reference.
const policyRefIndex = "galactic.datumapis.com/policy-refs"

// PolicyReconciler reports whether each TrafficPolicy is valid in its
// Accepted condition.
type PolicyReconciler struct {
	Client client.Client
}

// SetupWithManager registers the reconciler.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("trafficpolicy").
		// The managed-by label decides a reserved-name conflict, and a label
		// change does not bump the generation.
		For(&galacticv1alpha1.TrafficPolicy{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{}))).
		Complete(r)
}

// Reconcile implements reconcile.Reconciler.
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p galacticv1alpha1.TrafficPolicy
	if err := r.Client.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	cond := metav1.Condition{Type: ConditionAccepted, ObservedGeneration: p.Generation}
	model, errs := trafficpolicy.FromAPI(p.Spec, field.NewPath("spec"))
	switch {
	case IsReservedConflict(&p):
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonReservedName
		cond.Message = fmt.Sprintf("%q is reserved for the controller's default policy; a reference to this "+
			"object denies everything", galacticv1alpha1.DefaultPolicyName)
	case len(errs) > 0:
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonInvalid
		cond.Message = errs.ToAggregate().Error()
	default:
		cond.Status, cond.Reason = metav1.ConditionTrue, ReasonAccepted
		cond.Message = acceptedMessage(model)
	}
	before := p.DeepCopy()
	p.Status.ObservedGeneration = p.Generation
	meta.SetStatusCondition(&p.Status.Conditions, cond)
	if err := r.Client.Status().Patch(ctx, &p, client.MergeFrom(before)); err != nil {
		return ctrl.Result{}, fmt.Errorf("update TrafficPolicy %s status: %w", req.NamespacedName, err)
	}
	return ctrl.Result{}, nil
}

func acceptedMessage(p trafficpolicy.Policy) string {
	msg := fmt.Sprintf("%d rules compile to %d datapath entries", len(p.Rules), p.EntryCount())
	shadowed := trafficpolicy.Shadowed(p)
	unreachable := p.Unreachable()
	notes := make([]string, 0, len(unreachable)+len(shadowed))
	for _, i := range unreachable {
		notes = append(notes, fmt.Sprintf("rule %s can never match", p.Rules[i].Name))
	}
	for _, i := range slices.Sorted(maps.Keys(shadowed)) {
		notes = append(notes, fmt.Sprintf("rule %s is never reached after rule %s", p.Rules[i].Name,
			p.Rules[shadowed[i]].Name))
	}
	if len(notes) > 0 {
		msg += "; " + strings.Join(notes, "; ")
	}
	return msg
}

// DefaultPolicyReconciler provisions the reserved default policy in every
// namespace that holds a VPCAttachment, so it can be referenced by name. It
// never adopts or overwrites a conflicting object of that name: it reports
// the conflict and omitted references keep using the built-in default.
type DefaultPolicyReconciler struct {
	Client   client.Client
	Recorder events.EventRecorder
}

// SetupWithManager registers the reconciler. It reconciles namespaces,
// triggered by attachments and by the reserved policy itself.
func (r *DefaultPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	toNamespace := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: o.GetNamespace()}}}
	})
	isDefault := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetName() == galacticv1alpha1.DefaultPolicyName
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("default-trafficpolicy").
		For(&corev1.Namespace{}).
		Watches(&cloudv1alpha1.VPCAttachment{}, toNamespace).
		Watches(&galacticv1alpha1.TrafficPolicy{}, toNamespace, builder.WithPredicates(isDefault)).
		Complete(r)
}

// Reconcile implements reconcile.Reconciler. The request names a namespace.
func (r *DefaultPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ns := req.Name
	var namespace corev1.Namespace
	if err := r.Client.Get(ctx, client.ObjectKey{Name: ns}, &namespace); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !namespace.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	var attachments cloudv1alpha1.VPCAttachmentList
	if err := r.Client.List(ctx, &attachments, client.InNamespace(ns), client.Limit(1)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list VPCAttachments in %s: %w", ns, err)
	}
	if len(attachments.Items) == 0 {
		return ctrl.Result{}, nil
	}

	key := client.ObjectKey{Namespace: ns, Name: galacticv1alpha1.DefaultPolicyName}
	var existing galacticv1alpha1.TrafficPolicy
	err := r.Client.Get(ctx, key, &existing)
	switch {
	case apierrors.IsNotFound(err):
		p := DefaultPolicy(ns)
		if err := r.Client.Create(ctx, p); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("create %s: %w", key, err)
		}
		return ctrl.Result{}, nil
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get %s: %w", key, err)
	case existing.Labels[ManagedByLabel] != ManagedByValue:
		r.Recorder.Eventf(&existing, nil, corev1.EventTypeWarning, "ProvisioningConflict", "Provision",
			"%s already exists and is not managed by galactic-controller; it is left as is, omitted references "+
				"use the built-in default, and explicit references to it deny", galacticv1alpha1.DefaultPolicyName)
		return ctrl.Result{}, nil
	case !equalSpec(existing.Spec):
		// Only the controller can write this object, so drift means a
		// write that bypassed admission. Restore the one deny-all rule.
		before := existing.DeepCopy()
		existing.Spec = webhook.DefaultSpec()
		if err := r.Client.Patch(ctx, &existing, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, fmt.Errorf("restore %s: %w", key, err)
		}
	}
	return ctrl.Result{}, nil
}

func equalSpec(s galacticv1alpha1.TrafficPolicySpec) bool {
	d := webhook.DefaultSpec()
	return len(s.Rules) == 1 && s.Rules[0].Name == d.Rules[0].Name && s.Rules[0].Action == d.Rules[0].Action &&
		s.Rules[0].Match == nil
}

// DefaultPolicy is the controller-owned default policy for namespace ns.
func DefaultPolicy(ns string) *galacticv1alpha1.TrafficPolicy {
	return &galacticv1alpha1.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: galacticv1alpha1.DefaultPolicyName, Namespace: ns,
			Labels: map[string]string{ManagedByLabel: ManagedByValue},
		},
		Spec: webhook.DefaultSpec(),
	}
}

// BindingReconciler resolves each TrafficPolicyBinding's references and
// reports them in status.ingress and status.egress. It applies only those
// fields, so the per-node entries galactic-router writes are left alone.
type BindingReconciler struct {
	Client client.Client
}

// SetupWithManager registers the reconciler, indexing bindings by the
// policies they reference so a policy change requeues exactly those.
func (r *BindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &galacticv1alpha1.TrafficPolicyBinding{},
		policyRefIndex, func(o client.Object) []string {
			b := o.(*galacticv1alpha1.TrafficPolicyBinding)
			var refs []string
			for _, ref := range []*galacticv1alpha1.LocalPolicyReference{b.Spec.IngressPolicyRef, b.Spec.EgressPolicyRef} {
				if ref != nil {
					refs = append(refs, ref.Name)
				}
			}
			return refs
		}); err != nil {
		return fmt.Errorf("index bindings by policy: %w", err)
	}
	referencing := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		var bindings galacticv1alpha1.TrafficPolicyBindingList
		if err := mgr.GetClient().List(ctx, &bindings, client.InNamespace(o.GetNamespace()),
			client.MatchingFields{policyRefIndex: o.GetName()}); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "list bindings referencing policy", "policy", o.GetName())
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(bindings.Items))
		for _, b := range bindings.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&b)})
		}
		return reqs
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("trafficpolicybinding").
		For(&galacticv1alpha1.TrafficPolicyBinding{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&galacticv1alpha1.TrafficPolicy{}, referencing).
		Complete(r)
}

// Reconcile implements reconcile.Reconciler.
func (r *BindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var b galacticv1alpha1.TrafficPolicyBinding
	if err := r.Client.Get(ctx, req.NamespacedName, &b); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ingress, err := r.resolve(ctx, b.Namespace, b.Spec.IngressPolicyRef, b.Generation)
	if err != nil {
		return ctrl.Result{}, err
	}
	egress, err := r.resolve(ctx, b.Namespace, b.Spec.EgressPolicyRef, b.Generation)
	if err != nil {
		return ctrl.Result{}, err
	}
	keepTransitionTimes(b.Status.Ingress, &ingress)
	keepTransitionTimes(b.Status.Egress, &egress)

	apply := map[string]any{
		"apiVersion": galacticv1alpha1.GroupVersion.String(),
		"kind":       "TrafficPolicyBinding",
		"metadata":   map[string]any{"name": b.Name, "namespace": b.Namespace},
		"status": map[string]any{
			"observedGeneration": b.Generation,
			"ingress":            ingress,
			"egress":             egress,
		},
	}
	body, err := json.Marshal(apply)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Client.Status().Patch(ctx, &b, client.RawPatch(types.ApplyPatchType, body),
		client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply TrafficPolicyBinding %s status: %w", req.NamespacedName, err)
	}
	return ctrl.Result{}, nil
}

// resolve reads the referenced policy from the informer cache, whose
// NotFound is authoritative once the manager has synced, and resolves it.
func (r *BindingReconciler) resolve(ctx context.Context, ns string, ref *galacticv1alpha1.LocalPolicyReference,
	generation int64,
) (galacticv1alpha1.DirectionStatus, error) {
	if ref == nil {
		return Resolve(nil, nil, generation), nil
	}
	var p galacticv1alpha1.TrafficPolicy
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &p)
	switch {
	case apierrors.IsNotFound(err):
		return Resolve(ref, nil, generation), nil
	case err != nil:
		return galacticv1alpha1.DirectionStatus{}, fmt.Errorf("get TrafficPolicy %s/%s: %w", ns, ref.Name, err)
	}
	return Resolve(ref, &p, generation), nil
}

// keepTransitionTimes carries over a condition's transition time when its
// status did not change, which SetStatusCondition does for in-place updates
// but a freshly built status cannot.
func keepTransitionTimes(old *galacticv1alpha1.DirectionStatus, cur *galacticv1alpha1.DirectionStatus) {
	if old == nil {
		return
	}
	for i := range cur.Conditions {
		c := &cur.Conditions[i]
		if prev := meta.FindStatusCondition(old.Conditions, c.Type); prev != nil && prev.Status == c.Status {
			c.LastTransitionTime = prev.LastTransitionTime
		}
	}
}
