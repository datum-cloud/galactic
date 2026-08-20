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

// networkRuleFinalizer guards the design plan's Teardown Ordering on
// NetworkRule deletion: BGP-route withdrawal must complete before
// NAT/conntrack state is released — see reconcileDelete.
const networkRuleFinalizer = "galactic.datum.net/networkrule-teardown"

// networkRuleLabel is set to rule.Name on every BGPAdvertisement a
// NetworkRule owns (one per gateway node per non-empty VIP address family —
// see NetworkGatewayReconciler.applyBGPAdvertisements), so reconcileDelete
// can discover all of them with a List + label selector instead of
// reconstructing their names from the namespace's *current* gateway-node
// membership. A node that was registered when the rule was created and has
// since left would not appear in that reconstruction, leaving its
// advertisement never found and never withdrawn — see issue #367.
const networkRuleLabel = "galactic.datum.net/network-rule"

// NetworkRuleReconciler owns two pieces of NetworkRule per-object lifecycle
// that NetworkGatewayReconciler's aggregate, List-driven reconcile loop is
// the wrong place for:
//
//   - primary_node assignment, exactly once, at creation (assignPrimaryNode)
//     — guarded so a later reconcile never recomputes it (see
//     gateway.AssignPrimaryNode's doc comment for why recomputing would
//     cause an avoidable traffic flap).
//   - the finalizer-guarded Teardown Ordering on deletion (reconcileDelete).
//
// This deliberately diverges from BGPPeerReconciler's "no-op Reconcile,
// just a watch source" pattern: BGPPeer has no per-object lifecycle state
// of its own to own (its parent BGPRouter does all the work), but
// primary_node's immutability guarantee and the finalizer's ordering
// guarantee are inherently *per-NetworkRule-object* invariants that must be
// enforced from that object's own Reconcile call, not reconstructed from a
// List every time some other object changes.
//
// Both pieces are safe to run from every gateway node's galactic-router
// process (see isGatewayNode) without leader election (none exists
// anywhere in this codebase) because they are either idempotent (finalizer
// add/remove, BGPAdvertisement delete) or a pure function of inputs every
// gateway node observes identically (gateway.AssignPrimaryNode).
type NetworkRuleReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	NodeName string
}

// Reconcile reconciles a single NetworkRule's finalizer and primary_node
// assignment. Engine convergence and BGPAdvertisement wiring for accepted
// rules happen in NetworkGatewayReconciler, which watches NetworkRule and
// re-lists on every change (see ruleToGatewayRequests) — this reconciler
// never touches the gateway engine directly.
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

// updateAcceptedCondition ensures the Accepted condition is set once
// gateway nodes exist for this namespace. An earlier, Full-NAT-era version
// of this method (assignPrimaryNode) also computed and pinned
// status.primaryNode exactly once, via gateway.AssignPrimaryNode — DSR's
// anycast model has no primary/secondary node to assign at all (every
// gateway node serves every accepted rule identically, see
// networkgateway_controller.go's package doc comment), so that field and
// function no longer exist; this method keeps only the half of the old
// logic that's still meaningful.
//
// This is what networkrule_webhook.go's authorize doc comment promises
// happens here: "the Accepted condition on the NetworkRule itself is set
// by the future NetworkRule controller once the object has passed
// admission and been persisted" (a validating webhook can't write to the
// status of a request it hasn't admitted yet). Without it,
// NetworkGatewayReconciler's own Accepted gate on its rule-gathering loop
// would exclude every rule from every gateway node's vip_table and never
// create its BGPAdvertisement, forever — since no
// ValidatingWebhookConfiguration is deployed in this repo to set it any
// other way (config/webhook/ doesn't exist yet -- see the NetworkRule
// admission webhook's own known-gap note).
func (r *NetworkRuleReconciler) updateAcceptedCondition(ctx context.Context, rule *bgpv1alpha1.NetworkRule) error {
	nodes, err := gatewayNodeNames(ctx, r.Client, rule.Namespace)
	if err != nil {
		return err
	}

	ruleCopy := rule.DeepCopy()
	if len(nodes) == 0 {
		// No gateway nodes registered yet for this PoP. Surface this via
		// the Accepted condition rather than silently doing nothing — the
		// NetworkGateway watch (see gatewayToRuleRequests) re-queues this
		// rule as soon as a gateway node registers, so it is not parked
		// here until the next periodic resync.
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

// reconcileDelete performs the design plan's Teardown Ordering on
// NetworkRule deletion:
//
//  1. Withdraw the BGP route(s) — delete this rule's BGPAdvertisement
//     object(s) — before touching NAT/conntrack state. Removing NAT state
//     first while the route is still advertised risks blackholing in-flight
//     flows through a translation that no longer exists.
//  2. Release NAT/conntrack state. STUBBED (gateway.QuotaEnforcer) — this
//     call site is real and wired, the implementation behind it is not.
//
// Step 3 (rule_table row removal) is node-local and is performed
// independently by each gateway node's own NetworkGatewayReconciler /
// internal/gateway.Engine, which excludes a deleting rule from its desired
// state immediately (see that reconciler's rule-gathering loop) rather than
// waiting on this finalizer — coordinating "both gateway nodes have
// finished their own rule_table teardown" before releasing the finalizer
// would need a cross-node protocol the design plan does not specify, so
// this reconciler does not attempt one; the finalizer here only orders
// step 1 before step 2, on this reconciler's own timeline.
func (r *NetworkRuleReconciler) reconcileDelete(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(rule, networkRuleFinalizer) {
		return ctrl.Result{}, nil
	}

	// Listed by networkRuleLabel rather than reconstructed from the
	// namespace's current gateway-node membership (as a name-based lookup
	// would have to be) — this finds every advertisement this rule ever
	// caused to be created, including ones for a node that has since left
	// the namespace. See networkRuleLabel's doc comment and issue #367.
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

	// TODO(edge-gateway): this calls the real, wired gateway.QuotaEnforcer
	// interface, but with NoopQuotaEnforcer behind it — see that
	// interface's doc comment for why real per-tenant conntrack/NAT quota
	// release is deferred to Phase E.
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

// SetupWithManager registers the NetworkRuleReconciler with the manager.
//
// The NetworkGateway watch is the mirror image of
// NetworkGatewayReconciler's NetworkRule watch: both of this reconciler's
// jobs (isGatewayNode gating in Reconcile, primary-node assignment in
// assignPrimaryNode) are functions of the namespace's gateway-node pool, so
// a rule must be re-examined whenever that pool changes rather than waiting
// on its own periodic resync.
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
// its namespace — the inverse of ruleToGatewayRequests, and a deliberate
// broadcast for the same reason: a NetworkRule carries no gatewayRef, and
// every rule's Accepted condition and primary-node assignment depend on the
// namespace's whole gateway-node pool (see assignPrimaryNode). Without this,
// a rule created before any gateway node registered stays parked at
// Accepted=False — and therefore excluded from NetworkGatewayReconciler's
// rule-gathering loop — until the informer's periodic resync (10 hours by
// default).
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
