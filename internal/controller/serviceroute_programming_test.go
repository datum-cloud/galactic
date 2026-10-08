// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const testPSCRemoteNode = "psc-node-b"

func TestProgrammingAcknowledgmentFencesAndWithdrawal(t *testing.T) {
	r, p, _ := pscFixture(t)
	ctx := context.Background()
	key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	current := &networkv1alpha1.ServiceRoutePolicy{}
	_ = r.Get(ctx, key, current)
	if len(current.Status.Nodes) != 1 || !current.Status.Nodes[0].Ready || current.Status.Nodes[0].InputDigest == "" {
		t.Fatalf("nodes=%+v", current.Status.Nodes)
	}
	old := current.DeepCopy()
	current.Generation++
	if err := r.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := r.setNodeProgramming(ctx, old, "old", true); err == nil {
		t.Fatal("stale generation acknowledged")
	}
	current.Spec.ConsumerVPCRef.UID = "wrong"
	if err := r.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	_ = r.Get(ctx, key, current)
	if current.Status.Nodes[0].Ready || len(r.Applied) != 0 {
		t.Fatalf("invalid pin retained state: %+v", current.Status.Nodes)
	}
}

func TestRemoteProgrammingReportsBothPathHalves(t *testing.T) {
	r, p, _ := pscFixture(t)
	ctx := context.Background()
	producer := &cloudv1alpha1.VPCAttachment{}
	producerKey := types.NamespacedName{Namespace: "service", Name: "server"}
	if err := r.Get(ctx, producerKey, producer); err != nil {
		t.Fatal(err)
	}
	producer.Status.Node = testPSCRemoteNode
	if err := r.Update(ctx, producer); err != nil {
		t.Fatal(err)
	}
	endpoint := &networkv1alpha1.ServiceEndpoint{}
	key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
	_ = r.Get(ctx, key, endpoint)
	endpoint.Spec.DeliveryMode = networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal
	if err := r.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	for index, node := range []string{r.NodeName, testPSCRemoteNode} {
		router := &networkv1alpha1.BGPRouter{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "galactic-system",
				Name:      node,
			},
			Spec: networkv1alpha1.BGPRouterSpec{
				TargetRef: networkv1alpha1.TargetRef{
					Name: node,
				},
				SRv6Locator: "fd00:1234::/48",
				NodeID:      int32(index + 1),
			},
		}
		if err := r.Create(ctx, router); err != nil {
			t.Fatal(err)
		}
		vpc := map[string]string{r.NodeName: "vpc-identity", testPSCRemoteNode: "service-vpc"}[node]
		vrf := &networkv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "galactic-system",
				Name:      crdnames.BGPVRFInstanceName(vpc, node),
			},
			Spec: networkv1alpha1.BGPVRFInstanceSpec{
				RouterTarget: networkv1alpha1.RouterTarget{
					RouterRef: &networkv1alpha1.RouterRef{
						Name: node,
					},
				},
				VRFID: int32(index + 1),
			},
		}
		if err := r.Create(ctx, vrf); err != nil {
			t.Fatal(err)
		}
	}
	second := &ServiceRoutePolicyReconciler{
		Client:          r.Client,
		NodeName:        testPSCRemoteNode,
		FrontendEnabled: true,
		Programmer:      &retryRouteProgrammer{},
		Now:             r.Now,
	}
	for _, node := range []*ServiceRoutePolicyReconciler{r, second} {
		if _, err := node.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
	}
	current := &networkv1alpha1.ServiceRoutePolicy{}
	_ = r.Get(ctx, key, current)
	if len(current.Status.Nodes) != 2 || !current.Status.Nodes[0].Ready || !current.Status.Nodes[1].Ready ||
		current.Status.Nodes[0].InputDigest != current.Status.Nodes[1].InputDigest {
		t.Fatalf("remote reports=%+v", current.Status.Nodes)
	}
	if len(r.Applied[key]) != 1 || len(second.Applied[key]) != 1 {
		t.Fatal("remote halves not independently programmed")
	}
	producer.Status.Conditions[0].Status = metav1.ConditionFalse
	if err := r.Update(ctx, producer); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	_ = r.Get(ctx, key, current)
	if current.Status.Nodes[1].Ready || len(second.Applied) != 0 {
		t.Fatalf("withdrawn producer retained readiness=%+v", current.Status.Nodes)
	}
}

func TestDisablingFrontendWithdrawsNodeAcknowledgment(t *testing.T) {
	r, p, _ := pscFixture(t)
	ctx := context.Background()
	key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	r.FrontendEnabled = false
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	current := &networkv1alpha1.ServiceRoutePolicy{}
	if err := r.Get(ctx, key, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Nodes[0].Ready || len(r.Applied) != 0 {
		t.Fatal("disabled node retained programming proof")
	}
}
