// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

func newTestEgressPolicy(name, vpcRef string) *bgpv1alpha1.NetworkEgressPolicy {
	return &bgpv1alpha1.NetworkEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
		Spec:       bgpv1alpha1.NetworkEgressPolicySpec{VPCRef: vpcRef, VPCAttachmentRef: "attach-1"},
	}
}

func TestNetworkEgressPolicyReconciler_AssignsGatewayNodeOnce(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	gwB := newTestGateway(testNodeGWB)
	policy := newTestEgressPolicy("policy-1", "vpc-1")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkEgressPolicy{}).
		WithObjects(gwA, gwB, policy).
		Build()

	r := &NetworkEgressPolicyReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	req := ctrl.Request{NamespacedName: testRuleKey("policy-1")}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	got := &bgpv1alpha1.NetworkEgressPolicy{}
	if err := fakeClient.Get(context.Background(), testRuleKey("policy-1"), got); err != nil {
		t.Fatalf("get NetworkEgressPolicy: %v", err)
	}
	if got.Status.AssignedGatewayNode == "" {
		t.Fatal("AssignedGatewayNode was not set")
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		t.Error("Accepted condition was not set true")
	}

	firstAssignment := got.Status.AssignedGatewayNode

	// A second reconcile (e.g. triggered by an unrelated NetworkGateway
	// change) must not recompute the assignment -- gateway.AssignPrimaryNode's
	// own doc comment explains why silently recomputing would be a
	// correctness bug, not just a wasted computation.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("second Reconcile: unexpected error: %v", err)
	}
	got2 := &bgpv1alpha1.NetworkEgressPolicy{}
	if err := fakeClient.Get(context.Background(), testRuleKey("policy-1"), got2); err != nil {
		t.Fatalf("get NetworkEgressPolicy after second reconcile: %v", err)
	}
	if got2.Status.AssignedGatewayNode != firstAssignment {
		t.Errorf("AssignedGatewayNode changed across reconciles: %q -> %q", firstAssignment, got2.Status.AssignedGatewayNode)
	}
}

func TestNetworkEgressPolicyReconciler_NoGatewayNodesSetsNotAccepted(t *testing.T) {
	scheme := newRuleTestScheme(t)
	policy := newTestEgressPolicy("policy-1", "vpc-1")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkEgressPolicy{}).
		WithObjects(policy).
		Build()

	r := &NetworkEgressPolicyReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	req := ctrl.Request{NamespacedName: testRuleKey("policy-1")}

	// No NetworkGateway registered for this node at all -- isGatewayNode
	// gates the whole reconcile, so this must be a no-op, not an error.
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	got := &bgpv1alpha1.NetworkEgressPolicy{}
	if err := fakeClient.Get(context.Background(), testRuleKey("policy-1"), got); err != nil {
		t.Fatalf("get NetworkEgressPolicy: %v", err)
	}
	if got.Status.AssignedGatewayNode != "" {
		t.Errorf("AssignedGatewayNode = %q, want empty (this node is not a gateway node)", got.Status.AssignedGatewayNode)
	}
}

func TestNetworkEgressPolicyReconciler_SkipsNonGatewayNode(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	policy := newTestEgressPolicy("policy-1", "vpc-1")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkEgressPolicy{}).
		WithObjects(gwA, policy).
		Build()

	// "compute-node-1" (testComputeNodeName) is not a registered gateway
	// node -- assignment must not run from its process.
	r := &NetworkEgressPolicyReconciler{Client: fakeClient, Scheme: scheme, NodeName: testComputeNodeName}
	req := ctrl.Request{NamespacedName: testRuleKey("policy-1")}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	got := &bgpv1alpha1.NetworkEgressPolicy{}
	if err := fakeClient.Get(context.Background(), testRuleKey("policy-1"), got); err != nil {
		t.Fatalf("get NetworkEgressPolicy: %v", err)
	}
	if got.Status.AssignedGatewayNode != "" {
		t.Errorf("AssignedGatewayNode = %q, want empty (reconciler running on a non-gateway node)",
			got.Status.AssignedGatewayNode)
	}
}
