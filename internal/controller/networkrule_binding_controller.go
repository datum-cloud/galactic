// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// bindingNodeLabel is set on every ServiceVIPBinding NetworkRuleBindingReconciler
// writes, to gatewayNodeLabelValue of the node it was written for, so each
// node lists only its own bindings.
const bindingNodeLabel = "galactic.datum.net/binding-node"

// bindingManagedByLabel and bindingManagedByValue mark a ServiceVIPBinding as
// generated. NetworkRuleBindingReconciler deletes only bindings carrying them,
// so it never removes one it did not write.
const (
	bindingManagedByLabel = "app.kubernetes.io/managed-by"
	bindingManagedByValue = "galactic-router"
)

// conditionTypeBackendsBound is the per-node NetworkRule condition, as
// "<node>/BackendsBound", recording whether every binding node needs for the
// rule exists and reports Bound. Reasons are the reasonBindings* constants.
const conditionTypeBackendsBound = "BackendsBound"

// bindingTargetKind is the targetRef kind of every generated binding.
const bindingTargetKind = "Node"

const (
	// reasonBindingsBound: every backend of the rule on this node is bound.
	reasonBindingsBound = "Bound"

	// reasonBindingsPending: at least one binding is not Bound yet, or reports
	// why it cannot be.
	reasonBindingsPending = "BindingsNotBound"

	// reasonBindingsInvalid: the rule's spec cannot be built into bindings,
	// either a second IPv6 VIP or a selector that does not parse. Only nodes
	// that serve the rule report it, and they keep their bindings until the
	// spec is fixed.
	reasonBindingsInvalid = "InvalidRule"
)

// NetworkRuleBindingReconciler writes, on its own node, the ServiceVIPBindings
// that a NetworkRule's backends need: one per IPv6 VIP per backend whose
// VPCAttachment reports this node. It runs in galactic-router on every node.
//
// It is the only writer of generated bindings, and each node writes only its
// own, so gateway replicas never race and a gateway rollout never touches
// them. A binding is owned by its rule, so deleting the rule garbage-collects
// it, and the binding's own finalizer still lets ServiceVIPBindingReconciler
// remove its vip_xlat_table rows first. A backend that moves to another node,
// changes address, or stops matching the selector has its binding deleted
// here and a new one written by whichever node now hosts it. A rule whose
// spec cannot be built into bindings keeps the ones it has.
//
// The binding's egressKind comes from the attachment's interface mode, which
// is known before the backend's interface exists, and its vpcRef from the
// rule, which names the VRF the binding's rows go into. Both sides of the
// datapath derive the backend set from selectRuleBackends, and the binding's
// slot from its backend address and port, so the slot the gateway encodes and
// the row this node writes always agree.
//
// The rule's "<node>/BackendsBound" condition summarizes this node's bindings,
// so a rule that is Programmed on the gateways but cannot reach a backend on
// some node says so on the rule itself.
type NetworkRuleBindingReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	NodeName string
}

// Reconcile converges this node's generated bindings for one NetworkRule.
func (r *NetworkRuleBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rule := &bgpv1alpha1.NetworkRule{}
	if err := r.Get(ctx, req.NamespacedName, rule); err != nil {
		if apierrors.IsNotFound(err) {
			// Owner references garbage-collect the rule's bindings.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get NetworkRule %s: %w", req.NamespacedName, err)
	}
	if !rule.DeletionTimestamp.IsZero() {
		// The gateways keep serving a deleting rule until its routes are
		// withdrawn and drained, so its bindings stay until the rule is gone
		// and garbage collection removes them.
		return ctrl.Result{}, nil
	}

	if !meta.IsStatusConditionTrue(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		// Not accepted yet, or no longer: Accepted goes False whenever no
		// NetworkGateway exists in the namespace, which a delete and re-apply
		// of the gateways passes through. Deleting the bindings then would
		// remove every backend node's vip_xlat_table rows for a moment that
		// costs nothing to wait out, so existing bindings stay. The gateways
		// do not serve an unaccepted rule, so an idle binding draws no traffic.
		return ctrl.Result{}, nil
	}

	attachments, err := listVPCAttachments(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	desired, buildErr := r.desiredBindings(rule, attachments)
	if buildErr != nil {
		// The spec cannot be built into bindings: a second IPv6 VIP, or a
		// selector that does not parse. Deleting the bindings then would
		// remove every backend node's vip_xlat_table rows at once, while the
		// gateways still drain the rule's established flows toward them, so
		// an edit that is reverted minutes later would still have dropped
		// every connection. Existing bindings stay untouched until a valid
		// spec says otherwise, and the rule says why. A spec error does not
		// heal on retry, so none is requested: the fix bumps the generation,
		// which the predicate passes.
		existing, err := r.nodeBindings(ctx, rule)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err := r.publishCondition(ctx, rule, nil, buildErr, len(existing) > 0); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if err := r.applyBindings(ctx, rule, desired); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.publishCondition(ctx, rule, desired, nil, false); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// desiredBindings returns the bindings this node needs for rule: one for its
// IPv6 VIP per selected backend on this node. The datapath translates IPv6
// only, so a rule with no IPv6 VIP needs none, and ruleTranslatedVIP refuses a
// rule with more than one.
func (r *NetworkRuleBindingReconciler) desiredBindings(
	rule *bgpv1alpha1.NetworkRule, attachments []*cloudv1alpha1.VPCAttachment,
) ([]*bgpv1alpha1.ServiceVIPBinding, error) {
	vip, ok, err := ruleTranslatedVIP(rule)
	if err != nil || !ok {
		return nil, err
	}
	backends, _, err := selectRuleBackends(rule, attachments)
	if err != nil {
		return nil, err
	}

	var out []*bgpv1alpha1.ServiceVIPBinding
	for _, b := range backends {
		if b.node == r.NodeName {
			out = append(out, r.newBinding(rule, vip, b))
		}
	}
	return out, nil
}

// newBinding builds the binding for one VIP and one backend on this node.
func (r *NetworkRuleBindingReconciler) newBinding(
	rule *bgpv1alpha1.NetworkRule, vip netip.Addr, b ruleBackend,
) *bgpv1alpha1.ServiceVIPBinding {
	return &bgpv1alpha1.ServiceVIPBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: rule.Namespace,
			Name: crdnames.ServiceVIPBindingName(
				rule.Name, r.NodeName, vip.String(), b.addr.String(), int32(b.port)),
			Labels: map[string]string{
				networkRuleLabel:      rule.Name,
				bindingNodeLabel:      gatewayNodeLabelValue(r.NodeName),
				bindingManagedByLabel: bindingManagedByValue,
			},
		},
		Spec: bgpv1alpha1.ServiceVIPBindingSpec{
			TargetRef:      bgpv1alpha1.TargetRef{Kind: bindingTargetKind, Name: r.NodeName},
			VPCRef:         rule.Spec.VPCRef,
			VIPAddress:     vip.String(),
			Port:           rule.Spec.Port,
			Protocol:       rule.Spec.Protocol,
			BackendAddress: b.addr.String(),
			BackendPort:    int32(b.port),
			EgressKind:     b.egressKind,
		},
	}
}

// applyBindings creates or updates every binding in desired and deletes this
// node's other generated bindings for rule.
func (r *NetworkRuleBindingReconciler) applyBindings(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, desired []*bgpv1alpha1.ServiceVIPBinding,
) error {
	keep := make(map[string]bool, len(desired))
	var errs []error
	for _, want := range desired {
		keep[want.Name] = true
		binding := &bgpv1alpha1.ServiceVIPBinding{ObjectMeta: metav1.ObjectMeta{
			Namespace: want.Namespace, Name: want.Name,
		}}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, binding, func() error {
			if binding.Labels == nil {
				binding.Labels = make(map[string]string, len(want.Labels))
			}
			for k, v := range want.Labels {
				binding.Labels[k] = v
			}
			binding.Spec = want.Spec
			// Not a controller reference, and not blocking owner deletion:
			// the binding's own finalizer orders its teardown.
			return controllerutil.SetOwnerReference(rule, binding, r.Scheme)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("apply ServiceVIPBinding %s: %w", want.Name, err))
		}
	}

	existing, err := r.nodeBindings(ctx, rule)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for i := range existing {
		binding := &existing[i]
		if keep[binding.Name] {
			continue
		}
		if err := r.Delete(ctx, binding); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete stale ServiceVIPBinding %s: %w", binding.Name, err))
		}
	}
	return errors.Join(errs...)
}

// nodeBindings lists the generated bindings this node wrote for rule.
func (r *NetworkRuleBindingReconciler) nodeBindings(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule,
) ([]bgpv1alpha1.ServiceVIPBinding, error) {
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := r.List(ctx, list,
		client.InNamespace(rule.Namespace),
		client.MatchingLabels{
			networkRuleLabel:      rule.Name,
			bindingNodeLabel:      gatewayNodeLabelValue(r.NodeName),
			bindingManagedByLabel: bindingManagedByValue,
		},
	); err != nil {
		return nil, fmt.Errorf("list ServiceVIPBindings for NetworkRule %s: %w", rule.Name, err)
	}
	return list.Items, nil
}

// publishCondition sets this node's BackendsBound condition on rule, or removes
// it when the node hosts none of the rule's backends, so a rule's status names
// only the nodes that serve it.
//
// An invalid rule is reported only by the nodes that serve it: those that
// hold bindings for it (served), which a build error leaves in place. Every
// other node stays silent. The gateways already report the error on the
// rule, and a condition from every router node would cost a status write per
// node per edit, each conflicting with the others.
func (r *NetworkRuleBindingReconciler) publishCondition(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, desired []*bgpv1alpha1.ServiceVIPBinding,
	buildErr error, served bool,
) error {
	condType := backendsBoundConditionType(r.NodeName)
	stake := len(desired) > 0
	if buildErr != nil {
		stake = served
	}
	if !stake {
		// A node with no condition writes nothing: updateRuleCondition
		// writes only a change.
		return r.updateRuleCondition(ctx, rule, func(conds *[]metav1.Condition) bool {
			return meta.RemoveStatusCondition(conds, condType)
		})
	}

	cond := metav1.Condition{Type: condType}
	switch {
	case buildErr != nil:
		cond.Status = metav1.ConditionFalse
		cond.Reason = reasonBindingsInvalid
		cond.Message = buildErr.Error()
	default:
		unbound, err := r.unboundBindings(ctx, rule, desired)
		if err != nil {
			return err
		}
		if len(unbound) == 0 {
			cond.Status = metav1.ConditionTrue
			cond.Reason = reasonBindingsBound
			cond.Message = fmt.Sprintf("%d bindings bound on node %s", len(desired), r.NodeName)
		} else {
			cond.Status = metav1.ConditionFalse
			cond.Reason = reasonBindingsPending
			cond.Message = fmt.Sprintf("%d of %d bindings on node %s not bound: %s",
				len(unbound), len(desired), r.NodeName, cappedList(unbound, maxReadyFailures))
		}
	}
	return r.updateRuleCondition(ctx, rule, func(conds *[]metav1.Condition) bool {
		c := cond
		c.ObservedGeneration = rule.Generation
		return meta.SetStatusCondition(conds, c)
	})
}

// unboundBindings returns "vip -> backend: reason" for every desired binding
// that is not Bound yet, reading each one's current status.
func (r *NetworkRuleBindingReconciler) unboundBindings(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, desired []*bgpv1alpha1.ServiceVIPBinding,
) ([]string, error) {
	existing, err := r.nodeBindings(ctx, rule)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]*bgpv1alpha1.ServiceVIPBinding, len(existing))
	for i := range existing {
		byName[existing[i].Name] = &existing[i]
	}

	var unbound []string
	for _, want := range desired {
		label := net.JoinHostPort(want.Spec.VIPAddress, strconv.Itoa(int(want.Spec.Port))) + " -> " +
			net.JoinHostPort(want.Spec.BackendAddress, strconv.Itoa(int(want.Spec.BackendPort)))
		got, ok := byName[want.Name]
		if !ok {
			unbound = append(unbound, label+": not created yet")
			continue
		}
		bound := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound)
		switch {
		case bound == nil || bound.ObservedGeneration != got.Generation:
			unbound = append(unbound, label+": not reconciled yet")
		case bound.Status != metav1.ConditionTrue:
			unbound = append(unbound, label+": "+bound.Reason)
		}
	}
	sort.Strings(unbound)
	return unbound, nil
}

// updateRuleCondition applies mutate to rule's current conditions and writes
// them only if mutate reports a change. Every status write fans out to every
// reconciler watching NetworkRules, so an unconditional write would never
// settle.
func (r *NetworkRuleBindingReconciler) updateRuleCondition(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, mutate func(*[]metav1.Condition) bool,
) error {
	key := client.ObjectKeyFromObject(rule)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.NetworkRule{}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		if !mutate(&current.Status.Conditions) {
			return nil
		}
		return r.Status().Update(ctx, current)
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("update %s condition on NetworkRule %s: %w", conditionTypeBackendsBound, key, err)
	}
	return nil
}

// backendsBoundConditionType returns node's BackendsBound condition type. Rule
// status is shared by every node, so each node owns its own condition type and
// never overwrites another node's result.
func backendsBoundConditionType(node string) string {
	return node + "/" + conditionTypeBackendsBound
}

// SetupWithManager registers the NetworkRuleBindingReconciler with the manager.
func (r *NetworkRuleBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// A rule's bindings depend on its spec and on whether it is
		// Accepted. Other status writes, including this reconciler's own
		// conditions and the gateways' Programmed conditions, change neither.
		For(&bgpv1alpha1.NetworkRule{}, builder.WithPredicates(ruleBindingInputsChanged())).
		// An attachment can enter or leave the selection only of rules in
		// its VPC, or move to or from this node, so only the rules whose
		// VPC is its observed VPC are re-queued. An update maps both the old
		// and the new object, so an attachment moving between VPCs
		// re-queues the rules of both. Updates that change nothing
		// selectRuleBackends reads are dropped.
		Watches(&cloudv1alpha1.VPCAttachment{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return vpcRuleRequests(ctx, r.Client, obj)
			}),
			builder.WithPredicates(vpcAttachmentBackendChanged()),
		).
		// A binding's Bound condition feeds the rule's BackendsBound
		// condition, and a deleted binding must be rewritten.
		Watches(&bgpv1alpha1.ServiceVIPBinding{}, handler.EnqueueRequestsFromMapFunc(
			func(_ context.Context, obj client.Object) []ctrlreconcile.Request {
				return r.bindingRuleRequests(obj)
			}),
		).
		Named("networkrule-binding").
		Complete(r)
}

// ruleBindingInputsChanged passes NetworkRule events that can change the
// bindings it needs: a create or delete, a spec change, or a change to its
// Accepted condition.
func ruleBindingInputsChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldRule, okOld := e.ObjectOld.(*bgpv1alpha1.NetworkRule)
			newRule, okNew := e.ObjectNew.(*bgpv1alpha1.NetworkRule)
			if !okOld || !okNew {
				return true
			}
			if oldRule.Generation != newRule.Generation {
				return true
			}
			return meta.IsStatusConditionTrue(oldRule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) !=
				meta.IsStatusConditionTrue(newRule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted)
		},
	}
}

// vpcRuleRequests returns a reconcile request for every NetworkRule whose VPC
// is obj's observed VPC, the only rules whose backends obj can be. An
// attachment with no observed VPC is no rule's candidate and maps to nothing.
func vpcRuleRequests(ctx context.Context, c client.Client, obj client.Object) []ctrlreconcile.Request {
	attachment, ok := obj.(*cloudv1alpha1.VPCAttachment)
	if !ok || attachment.Status.VPC == "" {
		return nil
	}
	list := &bgpv1alpha1.NetworkRuleList{}
	if err := c.List(ctx, list); err != nil {
		log.FromContext(ctx).Error(err, "list NetworkRules for VPCAttachment change")
		return nil
	}
	var reqs []ctrlreconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.VPCRef != attachment.Status.VPC {
			continue
		}
		reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return reqs
}

// bindingRuleRequests maps a generated binding written for this node to its
// rule. Other nodes' bindings and hand-written ones map to nothing.
func (r *NetworkRuleBindingReconciler) bindingRuleRequests(obj client.Object) []ctrlreconcile.Request {
	labels := obj.GetLabels()
	if labels[bindingManagedByLabel] != bindingManagedByValue ||
		labels[bindingNodeLabel] != gatewayNodeLabelValue(r.NodeName) {
		return nil
	}
	rule := labels[networkRuleLabel]
	if rule == "" {
		return nil
	}
	return []ctrlreconcile.Request{{NamespacedName: client.ObjectKey{Namespace: obj.GetNamespace(), Name: rule}}}
}
