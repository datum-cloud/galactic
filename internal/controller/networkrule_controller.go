// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.datum.net/galactic/internal/gateway"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// networkRuleFinalizer orders teardown on NetworkRule deletion: BGP-route
// withdrawal must complete before NAT state is released. See reconcileDelete.
const networkRuleFinalizer = "galactic.datum.net/networkrule-teardown"

// networkRuleLabel is set to the rule's name on every BGPAdvertisement it owns,
// one per gateway node per non-empty VIP address family, so teardown can find
// them all with a label selector rather than reconstructing their names from the
// namespace's current gateway-node membership. A node registered when the rule
// was created and since departed would not appear in that reconstruction,
// leaving its advertisement never withdrawn.
const networkRuleLabel = "galactic.datum.net/network-rule"

// NetworkRuleReconciler owns the per-object NetworkRule lifecycle that
// NetworkGatewayReconciler's aggregate, list-driven loop is the wrong place
// for: setting the Accepted condition once gateway nodes exist, and the
// finalizer-guarded teardown ordering on deletion.
//
// That is a deliberate divergence from the no-op reconcilers elsewhere here,
// which exist only as watch sources. Those objects have no per-object lifecycle
// state of their own, while the finalizer's ordering guarantee is inherently a
// per-object invariant that must be enforced from that object's own Reconcile
// rather than reconstructed from a list whenever something else changes.
//
// Both jobs are safe to run from every gateway node's process without leader
// election, none existing anywhere in this codebase, because they are
// idempotent.
type NetworkRuleReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	NodeName string
}

// Reconcile reconciles one NetworkRule's finalizer and Accepted condition.
// Engine convergence and advertisement wiring for accepted rules happen in
// NetworkGatewayReconciler, which watches NetworkRule and re-lists on every
// change, so this reconciler never touches the gateway engine.
func (r *NetworkRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rule := &bgpv1alpha1.NetworkRule{}
	if err := r.Get(ctx, req.NamespacedName, rule); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get NetworkRule %s: %w", req.NamespacedName, err)
	}

	isGateway, err := isGatewayNode(ctx, r.Client, rule.Namespace, r.NodeName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("determine gateway-node membership for %s: %w", r.NodeName, err)
	}
	if !isGateway {
		return ctrl.Result{}, nil
	}

	if !rule.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, rule)
	}

	if !controllerutil.ContainsFinalizer(rule, networkRuleFinalizer) {
		patchBase := rule.DeepCopy()
		controllerutil.AddFinalizer(rule, networkRuleFinalizer)
		if err := r.Patch(ctx, rule, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer to NetworkRule %s: %w", req.NamespacedName, err)
		}
	}

	if err := r.updateAcceptedCondition(ctx, rule); err != nil {
		return ctrl.Result{}, fmt.Errorf("update Accepted condition for NetworkRule %s: %w", req.NamespacedName, err)
	}

	return ctrl.Result{}, nil
}

// updateAcceptedCondition sets the Accepted condition once gateway nodes exist
// for this namespace.
//
// The admission webhook cannot do it: a validating webhook cannot write to the
// status of a request it has not yet admitted. Without this, the gate
// NetworkGatewayReconciler applies while gathering rules would exclude every
// rule from every gateway node and never create its advertisement, since
// nothing else in this repo sets the condition.
func (r *NetworkRuleReconciler) updateAcceptedCondition(ctx context.Context, rule *bgpv1alpha1.NetworkRule) error {
	nodes, err := gatewayNodeNames(ctx, r.Client, rule.Namespace)
	if err != nil {
		return err
	}

	ruleCopy := rule.DeepCopy()
	if len(nodes) == 0 {
		// No gateway nodes registered for this PoP yet. Surfaced on the
		// Accepted condition rather than silently skipped. The NetworkGateway
		// watch re-queues this rule as soon as a node registers, so it is not
		// parked here until the next periodic resync.
		setRuleCondition(ruleCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeAccepted,
			Status:  metav1.ConditionFalse,
			Reason:  "NoGatewayNodes",
			Message: "no NetworkGateway nodes are registered in this namespace yet",
		})
		return r.Status().Update(ctx, ruleCopy)
	}

	if meta.IsStatusConditionTrue(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		return nil
	}
	setRuleCondition(ruleCopy, metav1.Condition{
		Type:    bgpv1alpha1.ConditionTypeAccepted,
		Status:  metav1.ConditionTrue,
		Reason:  "GatewayNodesRegistered",
		Message: "gateway nodes are registered for this namespace",
	})
	return r.Status().Update(ctx, ruleCopy)
}

// reconcileDelete orders teardown on NetworkRule deletion:
//
//  1. Withdraw the BGP routes, by deleting this rule's BGPAdvertisements,
//     before touching NAT state. Removing that state while the route is still
//     advertised risks blackholing in-flight flows through a translation that
//     no longer exists.
//  2. Release NAT and conntrack state. The call site is real and wired; the
//     implementation behind it is a no-op.
//
// Removing the datapath's own rule rows is node-local and done independently by
// each gateway node, which drops a deleting rule from its desired state
// immediately rather than waiting on this finalizer. Coordinating "every
// gateway node has finished" before releasing the finalizer would need a
// cross-node protocol that does not exist, so this only orders step 1 before
// step 2 on this reconciler's own timeline.
func (r *NetworkRuleReconciler) reconcileDelete(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(rule, networkRuleFinalizer) {
		return ctrl.Result{}, nil
	}

	// Listed by label rather than reconstructed from the namespace's current
	// gateway-node membership, which a name-based lookup would need. This finds
	// every advertisement the rule ever caused, including one for a node that
	// has since left.
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := r.List(ctx, advList,
		client.InNamespace(rule.Namespace),
		client.MatchingLabels{networkRuleLabel: rule.Name},
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("list BGPAdvertisements for NetworkRule %s/%s teardown: %w",
			rule.Namespace, rule.Name, err)
	}
	for i := range advList.Items {
		adv := &advList.Items[i]
		if delErr := r.Delete(ctx, adv); delErr != nil && !apierrors.IsNotFound(delErr) {
			return ctrl.Result{}, fmt.Errorf("withdraw BGPAdvertisement %s: %w", adv.Name, delErr)
		}
	}

	// TODO(edge-gateway): the QuotaEnforcer interface is real and wired, but
	// the implementation behind it here is a no-op. Real per-tenant quota
	// release is deferred.
	if err := (gateway.NoopQuotaEnforcer{}).Release(ctx, rule.Namespace+"/"+rule.Name); err != nil {
		return ctrl.Result{}, fmt.Errorf("release NAT/conntrack state for NetworkRule %s/%s: %w",
			rule.Namespace, rule.Name, err)
	}

	logger.Info("NetworkRule BGP route withdrawn; rule_table teardown proceeds independently on each gateway node",
		"networkRule", rule.Name)

	patchBase := rule.DeepCopy()
	controllerutil.RemoveFinalizer(rule, networkRuleFinalizer)
	if err := r.Patch(ctx, rule, client.MergeFrom(patchBase)); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer from NetworkRule %s/%s: %w", rule.Namespace, rule.Name, err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler with the manager.
//
// The NetworkGateway watch is the mirror of NetworkGatewayReconciler's
// NetworkRule watch: this reconciler's work depends on the namespace's
// gateway-node pool, so a rule must be re-examined whenever that pool changes
// rather than waiting on its own periodic resync.
func (r *NetworkRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.NetworkRule{}).
		Watches(&bgpv1alpha1.NetworkGateway{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return gatewayToRuleRequests(ctx, r.Client, obj)
			}),
		).
		Named("networkrule").
		Complete(r)
}

// gatewayToRuleRequests maps a NetworkGateway change to every NetworkRule in
// its namespace, the inverse of ruleToGatewayRequests and a deliberate
// broadcast for the same reason: a NetworkRule carries no gateway reference,
// and its Accepted condition depends on the whole gateway-node pool. Without
// it, a rule created before any gateway node registered stays unaccepted, and
// so excluded from every node's rule gathering, until the informer's periodic
// resync hours later.
func gatewayToRuleRequests(ctx context.Context, c client.Client, obj client.Object) []ctrlreconcile.Request {
	gw, ok := obj.(*bgpv1alpha1.NetworkGateway)
	if !ok {
		return nil
	}
	logger := log.FromContext(ctx)

	ruleList := &bgpv1alpha1.NetworkRuleList{}
	if err := c.List(ctx, ruleList, client.InNamespace(gw.Namespace)); err != nil {
		logger.Error(err, "list NetworkRules for NetworkGateway change", "networkGateway", gw.Name)
		return nil
	}
	reqs := make([]ctrlreconcile.Request, 0, len(ruleList.Items))
	for _, rule := range ruleList.Items {
		reqs = append(reqs, ctrlreconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: rule.Namespace, Name: rule.Name},
		})
	}
	return reqs
}
