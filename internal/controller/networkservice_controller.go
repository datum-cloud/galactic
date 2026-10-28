// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
)

// networkRuleFinalizer orders teardown on NetworkService deletion: BGP-route
// withdrawal must complete before NAT state is released. See reconcileDelete.
const networkRuleFinalizer = "galactic.datum.net/networkservice-teardown"

// networkRuleLabel is set to the rule's name on every BGPAdvertisement it owns,
// one per gateway node per non-empty VIP address family, so teardown can find
// them all with a label selector rather than reconstructing their names from the
// namespace's current gateway-node membership. A node registered when the rule
// was created and since departed would not appear in that reconstruction,
// leaving its advertisement never withdrawn.
const networkRuleLabel = "galactic.datum.net/network-rule"

// reasonGatewayNodesRegistered is the Accepted reason once gateway nodes exist
// in the rule's namespace, the only thing Accepted reports.
const reasonGatewayNodesRegistered = "GatewayNodesRegistered"

// gatewayNodeLabel is set on every BGPAdvertisement applyBGPAdvertisements
// creates. Its value is gatewayNodeLabelValue of the originating gateway node's
// name, so withdrawNodeAdvertisements can select one node's routes by label.
const gatewayNodeLabel = "galactic.datum.net/gateway-node"

// gatewayNodeLabelHashLen is how many hex characters of the node name's
// SHA-256 gatewayNodeLabelValue keeps when it has to shorten a name.
const gatewayNodeLabelHashLen = 10

// gatewayNodeLabelValue returns the gatewayNodeLabel value for nodeName.
// A label value is capped at 63 characters, but a node name can be up to 253
// (an FQDN, say), and a raw over-long value would fail every create and update
// of that node's advertisements. A name that is already a valid label value is
// returned unchanged. Any other is cut to a prefix, trimmed to end in an
// alphanumeric, and suffixed with "-" and a short hash of the full name, so the
// result is valid, deterministic, and distinct for two long names that share a
// prefix.
func gatewayNodeLabelValue(nodeName string) string {
	if len(validation.IsValidLabelValue(nodeName)) == 0 {
		return nodeName
	}
	sum := sha256.Sum256([]byte(nodeName))
	suffix := hex.EncodeToString(sum[:])[:gatewayNodeLabelHashLen]
	prefix := nodeName
	if maxPrefix := validation.LabelValueMaxLength - 1 - len(suffix); len(prefix) > maxPrefix {
		prefix = prefix[:maxPrefix]
	}
	prefix = strings.TrimRightFunc(prefix, func(c rune) bool {
		return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9')
	})
	if prefix == "" {
		return suffix
	}
	return prefix + "-" + suffix
}

// NetworkServiceReconciler owns the per-object NetworkService lifecycle that
// NetworkGatewayReconciler's aggregate, list-driven loop is the wrong place
// for: setting the Accepted condition once gateway nodes exist, the
// rule-wide summary conditions (summaryConditions), and the finalizer-guarded
// teardown ordering on deletion.
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
type NetworkServiceReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	NodeName string

	// APIReader reads from the API server, bypassing the informer cache.
	// Teardown uses it to find an advertisement another gateway node created
	// after this node's cache was last updated. Required.
	APIReader client.Reader

	// Scope is which NetworkServices this node's gateway serves and trusts.
	Scope ServiceScope
}

// staleAdvertisementRequeue is how long reconcileDelete waits before checking
// again after it found an advertisement its cache had missed.
const staleAdvertisementRequeue = time.Second

// Reconcile reconciles one NetworkService's finalizer, Accepted condition and
// summary conditions.
// Engine convergence and advertisement wiring for accepted rules happen in
// NetworkGatewayReconciler, which watches NetworkService and re-lists on every
// change, so this reconciler never touches the gateway engine.
func (r *NetworkServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rule := &bgpv1alpha1.NetworkService{}
	if err := r.Get(ctx, req.NamespacedName, rule); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get NetworkService %s: %w", req.NamespacedName, err)
	}

	gw, err := r.Scope.nodeServingGateway(ctx, r.Client, rule.Namespace, r.NodeName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("determine gateway-node membership for %s: %w", r.NodeName, err)
	}
	if gw == nil {
		return r.reconcileUnserved(ctx, rule)
	}

	if !rule.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, rule, gw.Namespace)
	}

	if !controllerutil.ContainsFinalizer(rule, networkRuleFinalizer) {
		patchBase := rule.DeepCopy()
		controllerutil.AddFinalizer(rule, networkRuleFinalizer)
		if err := r.Patch(ctx, rule, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer to NetworkService %s: %w", req.NamespacedName, err)
		}
	}

	if err := r.updateAcceptedCondition(ctx, rule, gw.Namespace); err != nil {
		return ctrl.Result{}, fmt.Errorf("update Accepted condition for NetworkService %s: %w", req.NamespacedName, err)
	}
	if err := updateSummaryConditions(ctx, r.Client, r.APIReader, r.Scope, req.NamespacedName); err != nil {
		return ctrl.Result{}, fmt.Errorf("update summary conditions for NetworkService %s: %w", req.NamespacedName, err)
	}

	return ctrl.Result{}, nil
}

// updateAcceptedCondition sets the Accepted condition once gateway nodes
// serve the rule (servingGateways). gwNamespace is the namespace of this
// node's serving NetworkGateway.
//
// For a rule in a gateway namespace, Accepted means only that: a gateway node
// is registered to serve it. It is not an ownership check: the platform API
// that writes the rule there verified the tenant owns the VPC, and RBAC on
// the namespace decides who else may write it.
//
// A rule in a tenant namespace, one holding no NetworkGateway, is checked
// here instead. It is accepted only when every VIP address falls in
// Scope.VIPPrefixes (VIPOutsidePool when one does not), a VPC in its own
// namespace carries its vpcRef (OwnershipVerified, or OwnershipDenied when
// none does) and no
// other rule already serves one of its VIP addresses on its protocol and port
// (VIPClaimed, see tenantVIPConflicts). Its backends come only from its own
// namespace (selectRuleBackends).
//
// NetworkGatewayReconciler programs only accepted rules, and withdraws the
// routes of one that loses Accepted. Nothing else sets the condition. It is
// written only when it changes, and follows the generation, or anything
// waiting on Accepted for the current spec (kubectl wait among them) treats it
// as stale.
func (r *NetworkServiceReconciler) updateAcceptedCondition(
	ctx context.Context, rule *bgpv1alpha1.NetworkService, gwNamespace string,
) error {
	cond, err := r.acceptedCondition(ctx, rule, gwNamespace)
	if err != nil {
		return err
	}
	if current := meta.FindStatusCondition(rule.Status.Conditions, cond.Type); current != nil &&
		current.Status == cond.Status && current.Reason == cond.Reason && current.Message == cond.Message &&
		current.ObservedGeneration == rule.Generation {
		return nil
	}
	ruleCopy := rule.DeepCopy()
	setRuleCondition(ruleCopy, cond)
	return r.Status().Update(ctx, ruleCopy)
}

// acceptedCondition computes rule's Accepted condition (updateAcceptedCondition).
func (r *NetworkServiceReconciler) acceptedCondition(
	ctx context.Context, rule *bgpv1alpha1.NetworkService, gwNamespace string,
) (metav1.Condition, error) {
	cond := metav1.Condition{Type: bgpv1alpha1.ConditionTypeAccepted, Status: metav1.ConditionFalse}
	nodes, err := r.Scope.servingGatewayNodeNames(ctx, r.Client, rule.Namespace)
	if err != nil {
		return cond, err
	}
	if len(nodes) == 0 {
		// No gateway nodes registered for this PoP yet. Surfaced on the
		// Accepted condition rather than silently skipped. The NetworkGateway
		// watch re-queues this rule as soon as a node registers, so it is not
		// parked here until the next periodic resync.
		cond.Reason = "NoGatewayNodes"
		cond.Message = "no NetworkGateway nodes are registered in this namespace yet"
		return cond, nil
	}
	if !ruleIsTenant(rule, gwNamespace) {
		cond.Status = metav1.ConditionTrue
		cond.Reason = reasonGatewayNodesRegistered
		cond.Message = "gateway nodes are registered for this namespace"
		return cond, nil
	}

	if ok, vip := r.Scope.vipsInPool(rule); !ok {
		cond.Reason = reasonVIPOutsidePool
		cond.Message = fmt.Sprintf("VIP address %q is outside the load balancer prefixes this location allocates", vip)
		return cond, nil
	}
	owns, why, err := ruleOwnsVPC(ctx, r.Client, rule)
	if err != nil {
		return cond, err
	}
	if !owns {
		cond.Reason = bgpv1alpha1.AcceptedReasonOwnershipDenied
		cond.Message = why
		return cond, nil
	}
	rules := &bgpv1alpha1.NetworkServiceList{}
	if err := r.List(ctx, rules); err != nil {
		return cond, fmt.Errorf("list NetworkServices: %w", err)
	}
	if owner, lost := tenantVIPConflicts(rules.Items, gwNamespace)[client.ObjectKeyFromObject(rule)]; lost {
		cond.Reason = reasonVIPClaimed
		cond.Message = fmt.Sprintf("NetworkService %s already serves one of its VIP addresses on %s port %d",
			owner, rule.Spec.Protocol, rule.Spec.Port)
		return cond, nil
	}
	cond.Status = metav1.ConditionTrue
	cond.Reason = bgpv1alpha1.AcceptedReasonOwnershipVerified
	cond.Message = fmt.Sprintf("VPC %q is in namespace %s, and gateway nodes in %s serve it",
		rule.Spec.VPCRef, rule.Namespace, gwNamespace)
	return cond, nil
}

// reconcileUnserved handles a rule no NetworkGateway on this node serves.
// A node serving a live rule sets its conditions. A live project rule that
// was accepted while project services were on, and that nothing serves now,
// has Accepted set False (reasonProjectServicesOff), so galactic-router stops
// writing bindings for it. A deleting rule that no NetworkGateway serves at
// all would otherwise keep its
// finalizer forever, and its namespace would never finish terminating, so any
// gateway process tears it down. Its generated objects are where a gateway
// serving it would have put them: in Scope.GatewayNamespace for a project
// rule, in its own namespace otherwise.
func (r *NetworkServiceReconciler) reconcileUnserved(
	ctx context.Context, rule *bgpv1alpha1.NetworkService,
) (ctrl.Result, error) {
	if rule.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.markProjectServiceUnserved(ctx, rule)
	}
	if !controllerutil.ContainsFinalizer(rule, networkRuleFinalizer) {
		return ctrl.Result{}, nil
	}
	nodes, err := r.Scope.servingGatewayNodeNames(ctx, r.Client, rule.Namespace)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list gateway nodes serving deleting NetworkService %s/%s: %w",
			rule.Namespace, rule.Name, err)
	}
	if len(nodes) > 0 {
		return ctrl.Result{}, nil
	}
	// A project rule's advertisements live in the gateway namespace whether
	// the switch is on or off: they may have been made while it was on.
	objNS := rule.Namespace
	if r.Scope.isProjectService(rule) {
		objNS = r.Scope.GatewayNamespace
	}
	return r.reconcileDelete(ctx, rule, objNS)
}

// markProjectServiceUnserved sets Accepted False on rule, a live rule no
// gateway on this node serves, when it is a project rule, project services
// are off and it is still accepted.
func (r *NetworkServiceReconciler) markProjectServiceUnserved(
	ctx context.Context, rule *bgpv1alpha1.NetworkService,
) error {
	if r.Scope.ProjectServices || !r.Scope.isProjectService(rule) ||
		!meta.IsStatusConditionTrue(rule.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		return nil
	}
	ruleCopy := rule.DeepCopy()
	setRuleCondition(ruleCopy, metav1.Condition{
		Type:    bgpv1alpha1.ConditionTypeAccepted,
		Status:  metav1.ConditionFalse,
		Reason:  reasonProjectServicesOff,
		Message: "the gateways serve only namespace " + r.Scope.GatewayNamespace,
	})
	return client.IgnoreNotFound(r.Status().Update(ctx, ruleCopy))
}

// reconcileDelete orders teardown on NetworkService deletion:
//
//  1. Withdraw the BGP routes, by deleting this rule's BGPAdvertisements,
//     before touching NAT state. Removing that state while the route is still
//     advertised risks blackholing in-flight flows through a translation that
//     no longer exists.
//  2. Release NAT and conntrack state. The call site is real and wired; the
//     implementation behind it is a no-op.
//
// Removing the datapath's own rule rows is node-local and done independently by
// each gateway node, after this step 1 rather than before it: while this
// finalizer is present and any advertisement carrying networkRuleLabel exists,
// NetworkGatewayReconciler keeps the rule loaded as draining, and once the last
// one is gone it waits ruleDrainDelay for the withdrawal to reach every peer
// before dropping it. The BGPAdvertisement watch is what wakes each node when
// the deletes below land. Coordinating "every gateway node has finished" before
// releasing the finalizer would need a cross-node protocol that does not
// exist, so the finalizer does not wait on the nodes.
//
// The cached list can miss an advertisement another gateway node created
// from a cache that had not yet seen the deletion timestamp. Before removing
// the finalizer the rule's advertisements are listed again through APIReader;
// any found there are deleted and the rule is requeued, keeping the finalizer
// until a pass finds none. A node that creates one after the finalizer is gone
// deletes it itself once its cache drops the rule (sweepOrphanedAdvertisements),
// and the advertisement's owner reference to the rule lets Kubernetes garbage
// collection delete it as a last resort.
func (r *NetworkServiceReconciler) reconcileDelete(
	ctx context.Context, rule *bgpv1alpha1.NetworkService, gwNamespace string,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(rule, networkRuleFinalizer) {
		return ctrl.Result{}, nil
	}

	// Listed by label rather than reconstructed from the namespace's current
	// gateway-node membership, which a name-based lookup would need. This finds
	// every advertisement the rule ever caused, including one for a node that
	// has since left.
	if _, err := deleteRuleAdvertisements(ctx, r.Client, r.Client, rule, gwNamespace); err != nil {
		return ctrl.Result{}, err
	}
	missed, err := deleteRuleAdvertisements(ctx, r.APIReader, r.Client, rule, gwNamespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	if missed > 0 {
		logger.Info("withdrew BGPAdvertisements the cache had missed; checking again before removing the finalizer",
			"networkRule", rule.Name, "count", missed)
		return ctrl.Result{RequeueAfter: staleAdvertisementRequeue}, nil
	}

	// TODO(edge-gateway): the QuotaEnforcer interface is real and wired, but
	// the implementation behind it here is a no-op. Real per-tenant quota
	// release is deferred.
	if err := (gateway.NoopQuotaEnforcer{}).Release(ctx, rule.Namespace+"/"+rule.Name); err != nil {
		return ctrl.Result{}, fmt.Errorf("release NAT/conntrack state for NetworkService %s/%s: %w",
			rule.Namespace, rule.Name, err)
	}

	logger.Info("NetworkService BGP route withdrawn; each gateway node drops it from vip_table after its drain delay",
		"networkRule", rule.Name)

	patchBase := rule.DeepCopy()
	controllerutil.RemoveFinalizer(rule, networkRuleFinalizer)
	// Another gateway process tearing the same rule down can remove the
	// finalizer first, and the rule is then gone.
	if err := client.IgnoreNotFound(r.Patch(ctx, rule, client.MergeFrom(patchBase))); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer from NetworkService %s/%s: %w", rule.Namespace, rule.Name, err)
	}
	return ctrl.Result{}, nil
}

// deleteRuleAdvertisements lists rule's BGPAdvertisements in objNS through
// reader and deletes each one through c that is not already being deleted. It returns how
// many it deleted.
func deleteRuleAdvertisements(
	ctx context.Context, reader client.Reader, c client.Client, rule *bgpv1alpha1.NetworkService, objNS string,
) (int, error) {
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := reader.List(ctx, advList, ruleSelector(rule, objNS)); err != nil {
		return 0, fmt.Errorf("list BGPAdvertisements for NetworkService %s/%s teardown: %w",
			rule.Namespace, rule.Name, err)
	}
	deleted := 0
	for i := range advList.Items {
		adv := &advList.Items[i]
		if !adv.DeletionTimestamp.IsZero() {
			continue
		}
		if err := c.Delete(ctx, adv); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return deleted, fmt.Errorf("withdraw BGPAdvertisement %s: %w", adv.Name, err)
		}
		deleted++
	}
	return deleted, nil
}

// SetupWithManager registers the reconciler with the manager.
//
// The NetworkGateway watch is the mirror of NetworkGatewayReconciler's
// NetworkService watch: this reconciler's work depends on the namespace's
// gateway-node pool, so a rule must be re-examined whenever that pool changes
// rather than waiting on its own periodic resync.
//
// A project rule's Accepted condition also depends on the VPCs in its
// namespace and on the VIPs other rules serve, so a VPC change re-queues the
// rules in its namespace, and a rule appearing, going or changing its spec
// re-queues every other rule sharing one of its VIP addresses. VPCs are
// watched only with Scope.ProjectServices on, so a gateway that serves no
// project rule needs no access to them.
func (r *NetworkServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.NetworkService{}).
		Watches(&bgpv1alpha1.NetworkGateway{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return gatewayToRuleRequests(ctx, r.Client, r.Scope, obj)
			}),
		)
	if r.Scope.ProjectServices {
		b = b.Watches(&cloudv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return namespaceRules(ctx, r.Client, obj.GetNamespace())
			}),
		)
	}
	return b.
		Watches(&bgpv1alpha1.NetworkService{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return sharedVIPRuleRequests(ctx, r.Client, obj)
			}),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("networkservice").
		Complete(r)
}

// namespaceRules returns a reconcile request for every NetworkService in
// namespace.
func namespaceRules(ctx context.Context, c client.Client, namespace string) []ctrlreconcile.Request {
	list := &bgpv1alpha1.NetworkServiceList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		log.FromContext(ctx).Error(err, "list NetworkServices for VPC change", "resource_namespace", namespace)
		return nil
	}
	reqs := make([]ctrlreconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return reqs
}

// sharedVIPRuleRequests returns a reconcile request for every NetworkService
// other than obj that lists one of obj's VIP addresses.
func sharedVIPRuleRequests(ctx context.Context, c client.Client, obj client.Object) []ctrlreconcile.Request {
	rule, ok := obj.(*bgpv1alpha1.NetworkService)
	if !ok {
		return nil
	}
	list := &bgpv1alpha1.NetworkServiceList{}
	if err := c.List(ctx, list); err != nil {
		log.FromContext(ctx).Error(err, "list NetworkServices for NetworkService change", "networkService", rule.Name)
		return nil
	}
	var reqs []ctrlreconcile.Request
	for i := range list.Items {
		other := &list.Items[i]
		if other.Namespace == rule.Namespace && other.Name == rule.Name {
			continue
		}
		if slices.ContainsFunc(other.Spec.VIPAddresses, func(v string) bool {
			return slices.Contains(rule.Spec.VIPAddresses, v)
		}) {
			reqs = append(reqs, ctrlreconcile.Request{NamespacedName: client.ObjectKeyFromObject(other)})
		}
	}
	return reqs
}

// gatewayToRuleRequests maps a NetworkGateway change to every NetworkService
// its namespace's gateways serve, the inverse of ruleToGatewayRequests and a deliberate
// broadcast for the same reason: a NetworkService carries no gateway reference,
// and its Accepted condition depends on the whole gateway-node pool. Without
// it, a rule created before any gateway node registered stays unaccepted, and
// so excluded from every node's rule gathering, until the informer's periodic
// resync hours later.
func gatewayToRuleRequests(
	ctx context.Context, c client.Client, scope ServiceScope, obj client.Object,
) []ctrlreconcile.Request {
	gw, ok := obj.(*bgpv1alpha1.NetworkGateway)
	if !ok {
		return nil
	}
	logger := log.FromContext(ctx)

	rules, _, err := scope.listServedNetworkServices(ctx, c, gw.Namespace)
	if err != nil {
		logger.Error(err, "list NetworkServices for NetworkGateway change", "networkGateway", gw.Name)
		return nil
	}
	reqs := make([]ctrlreconcile.Request, 0, len(rules))
	for _, rule := range rules {
		reqs = append(reqs, ctrlreconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: rule.Namespace, Name: rule.Name},
		})
	}
	return reqs
}
