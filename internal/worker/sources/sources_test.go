// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"net/netip"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	uidVA = "uid-va"
	uidEA = "uid-ea"
	uidEB = "uid-eb"
	nodeA = "node-a"
	vpcA  = "vpcA"
)

func TestKube(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	byUID := func(o client.Object) []string { return []string{string(o.GetUID())} }
	va := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Name: "va", Namespace: "p", UID: uidVA},
		Status: cloudv1alpha1.VPCAttachmentStatus{VPC: vpcA, Node: nodeA}}
	admitted := &galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Name: "ea", Namespace: "p", UID: uidEA},
		Status: galacticv1alpha1.EdgeAttachmentStatus{VPC: vpcA, NodeName: nodeA, Conditions: []metav1.Condition{{
			Type: galacticv1alpha1.EdgeAttachmentAdmitted, Status: metav1.ConditionTrue, Reason: "Admitted",
			LastTransitionTime: metav1.Now()}}}}
	pending := &galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Name: "eb", Namespace: "p", UID: uidEB},
		Status: galacticv1alpha1.EdgeAttachmentStatus{VPC: vpcA, NodeName: nodeA}}
	router := &bgpv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "galactic-system"}}
	router.Spec.TargetRef.Name = nodeA
	router.Spec.SRv6Locator = "2001:db8:1::/48"
	router.Spec.NodeID = 0x10
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(va, admitted, pending, router).
		WithIndex(&cloudv1alpha1.VPCAttachment{}, uidIndex, byUID).
		WithIndex(&galacticv1alpha1.EdgeAttachment{}, uidIndex, byUID).
		Build()
	k := Kube{Reader: c, Namespace: "galactic-system"}
	ctx := context.Background()

	for uid, want := range map[string]Attachment{
		uidVA: {UID: uidVA, Kind: KindVPCAttachment, VPC: vpcA, Node: nodeA, Admitted: true},
		uidEA: {UID: uidEA, Kind: KindEdgeAttachment, VPC: vpcA, Node: nodeA, Admitted: true},
		uidEB: {UID: uidEB, Kind: KindEdgeAttachment, VPC: vpcA, Node: nodeA, Admitted: false},
	} {
		got, ok, err := k.Attachment(ctx, uid)
		if err != nil || !ok || got != want {
			t.Errorf("Attachment(%s) = %+v, %t, %v; want %+v", uid, got, ok, err, want)
		}
	}
	if _, ok, err := k.Attachment(ctx, "missing"); ok || err != nil {
		t.Errorf("Attachment(missing) = %t, %v", ok, err)
	}
	loc, err := k.Locator(ctx, nodeA)
	if err != nil || loc != netip.MustParsePrefix("2001:db8:1:10::/64") {
		t.Errorf("Locator(node-a) = %s, %v", loc, err)
	}
	if loc, err := k.Locator(ctx, "node-b"); err != nil || loc.IsValid() {
		t.Errorf("Locator(node-b) = %s, %v; want none", loc, err)
	}
}
