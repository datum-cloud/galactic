// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/serviceroute"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const testServiceRouteTenantNamespace = "tenant"

type retryRouteProgrammer struct {
	applyCalls  int
	removeCalls int
	failApply   int
	failRemove  int
}

func (*retryRouteProgrammer) Initialize() error { return nil }

func (p *retryRouteProgrammer) Apply(serviceroute.RouteIntent) error {
	p.applyCalls++
	if p.applyCalls == p.failApply {
		return errors.New("apply failed")
	}
	return nil
}

func (p *retryRouteProgrammer) Remove(serviceroute.RouteIntent) error {
	p.removeCalls++
	if p.removeCalls == p.failRemove {
		return errors.New("remove failed")
	}
	return nil
}

func TestServiceRouteReplacePolicyResumesPartialApply(t *testing.T) {
	programmer := &retryRouteProgrammer{failApply: 2}
	reconciler := &ServiceRoutePolicyReconciler{Programmer: programmer}
	policy := types.NamespacedName{Namespace: "platform", Name: "dns"}
	intents := []serviceroute.RouteIntent{
		{Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: "a"}},
		{Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: "b"}},
	}

	if err := reconciler.replacePolicy(policy, intents); err == nil {
		t.Fatal("first replacePolicy succeeded, want injected failure")
	}
	if got := len(reconciler.Applied[policy]); got != 1 {
		t.Fatalf("tracked intents after partial apply = %d, want 1", got)
	}
	programmer.failApply = 0
	if err := reconciler.replacePolicy(policy, intents); err != nil {
		t.Fatalf("retry replacePolicy: %v", err)
	}
	if programmer.applyCalls != 3 {
		t.Fatalf("Apply calls = %d, want 3 (successful intent was not replayed)", programmer.applyCalls)
	}
	if got := len(reconciler.Applied[policy]); got != 2 {
		t.Fatalf("tracked intents after retry = %d, want 2", got)
	}
}

func TestServiceRouteRemovePolicyResumesPartialRemove(t *testing.T) {
	programmer := &retryRouteProgrammer{failRemove: 2}
	policy := types.NamespacedName{Namespace: "platform", Name: "dns"}
	reconciler := &ServiceRoutePolicyReconciler{
		Programmer: programmer,
		Applied: map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent{
			policy: {
				{Namespace: testServiceRouteTenantNamespace, Name: "a"}: {
					Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: "a"},
				},
				{Namespace: testServiceRouteTenantNamespace, Name: "b"}: {
					Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: "b"},
				},
			},
		},
	}

	if err := reconciler.removePolicy(policy); err == nil {
		t.Fatal("first removePolicy succeeded, want injected failure")
	}
	if got := len(reconciler.Applied[policy]); got != 1 {
		t.Fatalf("tracked intents after partial remove = %d, want 1", got)
	}
	programmer.failRemove = 0
	if err := reconciler.removePolicy(policy); err != nil {
		t.Fatalf("retry removePolicy: %v", err)
	}
	if programmer.removeCalls != 3 {
		t.Fatalf("Remove calls = %d, want 3 (successful removal was not replayed)", programmer.removeCalls)
	}
	if _, ok := reconciler.Applied[policy]; ok {
		t.Fatal("policy remains tracked after successful retry")
	}
}

func TestServiceRouteSIDResolverUsesConfiguredBGPNamespace(t *testing.T) {
	const (
		bgpNamespace = "routing-system"
		node         = testNAT66NodeB
		vpc          = "vpc-b"
		locator      = "fd00:1234::/48"
		vrfID        = int32(42)
	)
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	router := &networkv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: bgpNamespace, Name: "router-b"},
		Spec: networkv1alpha1.BGPRouterSpec{
			TargetRef: networkv1alpha1.TargetRef{Name: node}, SRv6Locator: locator, NodeID: 7,
		},
	}
	vrf := &networkv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: bgpNamespace, Name: crdnames.BGPVRFInstanceName(vpc, node)},
		Spec: networkv1alpha1.BGPVRFInstanceSpec{
			RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: router.Name}},
			VRFID:        vrfID,
		},
	}
	reconciler := &ServiceRoutePolicyReconciler{
		Client:       fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, vrf).Build(),
		BGPNamespace: bgpNamespace,
	}
	attachment := &cloudv1alpha1.VPCAttachment{Status: cloudv1alpha1.VPCAttachmentStatus{Node: node, VPC: vpc}}
	got, err := reconciler.sidResolver(context.Background())(attachment)
	if err != nil {
		t.Fatalf("resolve SID: %v", err)
	}
	want, err := srv6.ComputeSID(locator, 7, vrfID, networkv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(net.IP(want.AsSlice())) {
		t.Fatalf("SID = %s, want %s", got, want)
	}
}

func TestServiceRouteSIDResolverRejectsWrongRouterNode(t *testing.T) {
	const bgpNamespace = "routing-system"
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	router := &networkv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: bgpNamespace, Name: "router-b"},
		Spec: networkv1alpha1.BGPRouterSpec{
			TargetRef: networkv1alpha1.TargetRef{Name: "wrong-node"}, SRv6Locator: "fd00:1234::/48", NodeID: 7,
		},
	}
	vrf := &networkv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: bgpNamespace, Name: crdnames.BGPVRFInstanceName("vpc-b", testNAT66NodeB),
		},
		Spec: networkv1alpha1.BGPVRFInstanceSpec{
			RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: router.Name}},
			VRFID:        42,
		},
	}
	reconciler := &ServiceRoutePolicyReconciler{
		Client:       fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, vrf).Build(),
		BGPNamespace: bgpNamespace,
	}
	attachment := &cloudv1alpha1.VPCAttachment{
		Status: cloudv1alpha1.VPCAttachmentStatus{Node: testNAT66NodeB, VPC: "vpc-b"},
	}
	if _, err := reconciler.sidResolver(context.Background())(attachment); err == nil {
		t.Fatal("resolve SID succeeded for a router targeting the wrong node")
	}
}
