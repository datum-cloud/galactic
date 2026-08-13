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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.datum.net/galactic/internal/gateway"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// NetworkEgressPolicyReconciler owns NetworkEgressPolicy's one piece of
// per-object lifecycle state: status.assignedGatewayNode, assigned exactly
// once at creation (datum-cloud/enhancements#865, design plan §4.5),
// mirroring NetworkRuleReconciler.assignPrimaryNode almost exactly —
// gateway.AssignPrimaryNode's own doc comment explains why silently
// recomputing an existing assignment on a later reconcile would be a
// correctness bug (an avoidable traffic flap if the gateway-node pool
// later changes), not just a wasted computation.
//
// Unlike NetworkRuleReconciler, this reconciler carries no finalizer and no
// BGP-withdrawal teardown ordering: NetworkEgressPolicy owns no
// BGPAdvertisement of its own to withdraw (the gateway's own
// EgressAddress/EgressSID advertisements are independent of any single
// policy, and a tenant VRF's default route is a compute-node-local kernel
// resource internal/egressroute's route reconciler owns, not something
// this reconciler needs to order against). Deletion needs no special
// handling at all: internal/egressroute's route reconciler simply stops
// seeing an accepted policy for that VPC on its next periodic pass and
// removes the route then — no cross-node coordination to get right here.
//
// Safe to run from every gateway node's galactic-gateway process (see
// isGatewayNode) without leader election, for the identical reason
// NetworkRuleReconciler's own doc comment gives: assignGatewayNode is a
// pure function of inputs every gateway node observes identically
// (gateway.AssignPrimaryNode).
type NetworkEgressPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	NodeName string
}

// Reconcile reconciles a single NetworkEgressPolicy's gateway-node
// assignment.
func (r *NetworkEgressPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	policy := &bgpv1alpha1.NetworkEgressPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get NetworkEgressPolicy %s: %w", req.NamespacedName, err)
	}

	isGateway, err := isGatewayNode(ctx, r.Client, policy.Namespace, r.NodeName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("determine gateway-node membership for %s: %w", r.NodeName, err)
	}
	if !isGateway {
		return ctrl.Result{}, nil
	}

	if !policy.DeletionTimestamp.IsZero() {
		// No finalizer, nothing to tear down here — see this type's doc
		// comment.
		return ctrl.Result{}, nil
	}

	if err := r.assignGatewayNode(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("assign gateway node for NetworkEgressPolicy %s: %w", req.NamespacedName, err)
	}

	return ctrl.Result{}, nil
}

// assignGatewayNode sets policy.Status.AssignedGatewayNode exactly once —
// mirrors NetworkRuleReconciler.assignPrimaryNode's identical structure
// (immutability guard, Accepted condition gated on the gateway-node pool
// existing) — see that method's doc comment for why the webhook can't set
// Accepted itself.
func (r *NetworkEgressPolicyReconciler) assignGatewayNode(
	ctx context.Context, policy *bgpv1alpha1.NetworkEgressPolicy,
) error {
	nodes, err := gatewayNodeNames(ctx, r.Client, policy.Namespace)
	if err != nil {
		return err
	}

	policyCopy := policy.DeepCopy()
	if len(nodes) == 0 {
		setEgressPolicyCondition(policyCopy, metav1.Condition{
			Type:    bgpv1alpha1.ConditionTypeAccepted,
			Status:  metav1.ConditionFalse,
			Reason:  "NoGatewayNodes",
			Message: "no NetworkGateway nodes are registered in this namespace yet",
		})
		return r.Status().Update(ctx, policyCopy)
	}

	changed := false
	if policy.Status.AssignedGatewayNode == "" {
		assigned, err := gateway.AssignPrimaryNode(policy.Spec.VPCRef, nodes)
		if err != nil {
			return fmt.Errorf("assign gateway node: %w", err)
		}
		policyCopy.Status.AssignedGatewayNode = assigned
		policyCopy.Status.ObservedGeneration = policy.Generation
		changed = true
	}

	if !meta.IsStatusConditionTrue(policy.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		setEgressPolicyCondition(policyCopy, metav1.Condition{
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
	return r.Status().Update(ctx, policyCopy)
}

// SetupWithManager registers the NetworkEgressPolicyReconciler with the
// manager. The NetworkGateway watch mirrors NetworkRuleReconciler's own:
// assignGatewayNode is a function of the namespace's gateway-node pool, so
// a policy must be re-examined whenever that pool changes.
func (r *NetworkEgressPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.NetworkEgressPolicy{}).
		Watches(&bgpv1alpha1.NetworkGateway{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
				return gatewayToEgressPolicyRequests(ctx, r.Client, obj)
			}),
		).
		Named("networkegresspolicy").
		Complete(r)
}

// gatewayToEgressPolicyRequests maps a NetworkGateway change to every
// NetworkEgressPolicy in its namespace — the same broadcast pattern
// gatewayToRuleRequests uses for NetworkRule, for the identical reason: a
// NetworkEgressPolicy carries no gatewayRef, and its assignment depends on
// the namespace's whole gateway-node pool.
func gatewayToEgressPolicyRequests(ctx context.Context, c client.Client, obj client.Object) []ctrlreconcile.Request {
	gw, ok := obj.(*bgpv1alpha1.NetworkGateway)
	if !ok {
		return nil
	}
	logger := log.FromContext(ctx)

	policyList := &bgpv1alpha1.NetworkEgressPolicyList{}
	if err := c.List(ctx, policyList, client.InNamespace(gw.Namespace)); err != nil {
		logger.Error(err, "list NetworkEgressPolicies for NetworkGateway change", "networkGateway", gw.Name)
		return nil
	}
	reqs := make([]ctrlreconcile.Request, 0, len(policyList.Items))
	for _, policy := range policyList.Items {
		reqs = append(reqs, ctrlreconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name},
		})
	}
	return reqs
}
