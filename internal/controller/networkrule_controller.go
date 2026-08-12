// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"go.datum.net/galactic/internal/gateway"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// networkRuleFinalizer guards the design plan's Teardown Ordering on
// NetworkRule deletion: BGP-route withdrawal must complete before
// NAT/conntrack state is released — see reconcileDelete.
const networkRuleFinalizer = "galactic.datum.net/networkrule-teardown"

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

	if err := r.assignPrimaryNode(ctx, rule); err != nil {
		return ctrl.Result{}, fmt.Errorf("assign primary node for NetworkRule %s: %w", req.NamespacedName, err)
	}

	return ctrl.Result{}, nil
}

// assignPrimaryNode sets rule.Status.PrimaryNode exactly once — if it is
// already set, assigning it again is skipped (see gateway.AssignPrimaryNode's
// doc comment for why silently recomputing it would be a correctness bug,
// not just a wasted computation) — and also ensures the Accepted condition
// is set once gateway nodes exist for this namespace.
//
// That second half is what networkrule_webhook.go's authorize doc comment
// promises happens here: "the Accepted condition on the NetworkRule itself
// is set by the future NetworkRule controller once the object has passed
// admission and been persisted" (a validating webhook can't write to the
// status of a request it hasn't admitted yet). Without it,
// NetworkGatewayReconciler's own Accepted gate on its rule-gathering loop
// would exclude every rule from every gateway node's rule_table and never
// create its BGPAdvertisement, forever — since no
// ValidatingWebhookConfiguration is deployed in this repo to set it any
// other way (config/webhook/ doesn't exist yet -- see the NetworkRule
// admission webhook's own known-gap note).
func (r *NetworkRuleReconciler) assignPrimaryNode(ctx context.Context, rule *bgpv1alpha1.NetworkRule) error {
	nodes, err := gatewayNodeNames(ctx, r.Client, rule.Namespace)
	if err != nil {
		return err
	}

	ruleCopy := rule.DeepCopy()
	if len(nodes) == 0 {
		// No gateway nodes registered yet for this PoP. Surface this via
		// the Accepted condition rather than silently doing nothing — the
		// next NetworkGateway create event re-triggers this rule via
		// ruleToGatewayRequests's inverse (NetworkGatewayReconciler watches
		// NetworkRule, not the other way around, so this reconciler relies
		// on this NetworkRule's own periodic resync to retry).
		setRuleCondition(ruleCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeAccepted,
			Status:  metav1.ConditionFalse,
			Reason:  "NoGatewayNodes",
			Message: "no NetworkGateway nodes are registered in this namespace yet",
		})
		return r.Status().Update(ctx, ruleCopy)
	}

	changed := false
	if rule.Status.PrimaryNode == "" {
		primary, err := gateway.AssignPrimaryNode(rule.Spec.VPCRef, nodes)
		if err != nil {
			return fmt.Errorf("assign primary node: %w", err)
		}
		ruleCopy.Status.PrimaryNode = primary
		ruleCopy.Status.ObservedGeneration = rule.Generation
		changed = true
	}

	// Gated on IsStatusConditionTrue, not on "PrimaryNode was just assigned
	// above", so a rule whose PrimaryNode was already set on an earlier
	// reconcile (e.g. one that predates this fix) still gets Accepted=True
	// here instead of being skipped forever by the early per-field checks
	// above.
	if !meta.IsStatusConditionTrue(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		setRuleCondition(ruleCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeAccepted,
			Status:  metav1.ConditionTrue,
			Reason:  "GatewayNodesRegistered",
			Message: "gateway nodes are registered for this namespace",
		})
		changed = true
	}

	if !changed {
		return nil
	}
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

	nodeNames, err := gatewayNodeNames(ctx, r.Client, rule.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list gateway nodes for NetworkRule %s/%s teardown: %w",
			rule.Namespace, rule.Name, err)
	}

	for _, name := range bgpAdvertisementNamesForRule(rule, nodeNames) {
		adv := &bgpv1alpha1.BGPAdvertisement{}
		key := types.NamespacedName{Namespace: rule.Namespace, Name: name}
		err := r.Get(ctx, key, adv)
		switch {
		case apierrors.IsNotFound(err):
			// already withdrawn
		case err != nil:
			return ctrl.Result{}, fmt.Errorf("get BGPAdvertisement %s for teardown: %w", name, err)
		default:
			if delErr := r.Delete(ctx, adv); delErr != nil && !apierrors.IsNotFound(delErr) {
				return ctrl.Result{}, fmt.Errorf("withdraw BGPAdvertisement %s: %w", name, delErr)
			}
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
func (r *NetworkRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.NetworkRule{}).
		Named("networkrule").
		Complete(r)
}

// bgpAdvertisementNamesForRule returns the deterministic BGPAdvertisement
// object name(s) for rule — one per gateway node in nodeNames per
// non-empty VIP address family, matching
// NetworkGatewayReconciler.applyBGPAdvertisements's naming convention
// exactly (including the node-name qualifier — see that method's doc
// comment for why it's required, not cosmetic), so this reconciler's
// teardown always finds every object that reconciler created across every
// gateway node, not just the first one to have reconciled this rule.
func bgpAdvertisementNamesForRule(rule *bgpv1alpha1.NetworkRule, nodeNames []string) []string {
	var hasV4, hasV6 bool
	for _, v := range rule.Spec.VIPAddresses {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			continue
		}
		if addr.Is4() {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	var names []string
	for _, node := range nodeNames {
		if hasV4 {
			names = append(names, rule.Name+"-"+node+"-v4")
		}
		if hasV6 {
			names = append(names, rule.Name+"-"+node+"-v6")
		}
	}
	return names
}
