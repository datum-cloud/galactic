// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/srv6"
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
		Spec: cloudv1alpha1.VPCAttachmentSpec{Interface: cloudv1alpha1.VPCAttachmentInterface{
			Addresses: []cloudv1alpha1.IPAddress{"2001:db8:10::5/64", "192.0.2.5/24"},
		}},
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
		uidVA: {UID: uidVA, Kind: KindVPCAttachment, VPC: vpcA, Node: nodeA, Admitted: true,
			Addresses: []netip.Addr{netip.MustParseAddr("2001:db8:10::5"), netip.MustParseAddr("192.0.2.5")}},
		uidEA: {UID: uidEA, Kind: KindEdgeAttachment, VPC: vpcA, Node: nodeA, Admitted: true},
		uidEB: {UID: uidEB, Kind: KindEdgeAttachment, VPC: vpcA, Node: nodeA, Admitted: false},
	} {
		got, ok, err := k.Attachment(ctx, uid)
		if err != nil || !ok || !reflect.DeepEqual(got, want) {
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

// TestKubeBackendBindings reads the ServiceVIPBindings of a node in the
// gateway namespace whose backend hashes to a slot, and trusts a binding as
// Bound only for its current generation, with its source authority
// enforced, while it is not being deleted.
func TestKubeBackendBindings(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	const gwNS = "galactic-system"
	addr := netip.MustParseAddr("2001:db8:10::5")
	slot := srv6.BackendSlot(addr, 8080)
	bound := func(gen int64) []metav1.Condition {
		return []metav1.Condition{{Type: bgpv1alpha1.ConditionTypeBound, Status: metav1.ConditionTrue,
			Reason: "Bound", ObservedGeneration: gen, LastTransitionTime: metav1.Now()}}
	}
	binding := func(name, ns, node, backend string, port int32, gen int64, conds []metav1.Condition,
	) *bgpv1alpha1.ServiceVIPBinding {
		return &bgpv1alpha1.ServiceVIPBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: gen},
			Spec: bgpv1alpha1.ServiceVIPBindingSpec{TargetRef: bgpv1alpha1.TargetRef{Name: node}, VPCRef: vpcA,
				VIPAddress: "2001:db8:ff::1", Port: 80, Protocol: "tcp", BackendAddress: backend,
				BackendPort: port, EgressKind: bgpv1alpha1.ServiceVIPBindingEgressKindTap},
			Status: bgpv1alpha1.ServiceVIPBindingStatus{Conditions: conds},
		}
	}
	deleting := binding("b-deleting", gwNS, nodeA, addr.String(), 8080, 1, bound(1))
	deleting.Finalizers = []string{"galactic.datumapis.com/test"}
	deleting.DeletionTimestamp = &metav1.Time{Time: time.Unix(1_700_000_000, 0)}
	unenforced := binding("b-source", gwNS, nodeA, addr.String(), 8080, 1, bound(1))
	unenforced.Spec.SourceRef = &bgpv1alpha1.ServiceVIPBindingSourceReference{Generation: 1, Namespace: "p",
		Name: "svc", UID: "u", AllocationUID: "a"}
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(
			binding("b-bound", gwNS, nodeA, addr.String(), 8080, 2, bound(2)),
			binding("b-stale", gwNS, nodeA, addr.String(), 8080, 3, bound(2)),
			binding("b-none", gwNS, nodeA, addr.String(), 8080, 1, nil),
			unenforced,
			deleting,
			binding("b-other-port", gwNS, nodeA, addr.String(), 8081, 1, bound(1)),
			binding("b-other-node", gwNS, "node-b", addr.String(), 8080, 1, bound(1)),
			binding("b-other-ns", "p", nodeA, addr.String(), 8080, 1, bound(1)),
			binding("b-ipv4", gwNS, nodeA, "192.0.2.5", 8080, 1, bound(1)),
			binding("b-mapped", gwNS, nodeA, "::ffff:192.0.2.5", 8080, 1, bound(1)),
		).
		WithIndex(&bgpv1alpha1.ServiceVIPBinding{}, bindingNodeIndex, bindingNode).
		Build()
	k := Kube{Reader: c, Namespace: gwNS, GatewayNamespace: gwNS}
	got, err := k.BackendBindings(context.Background(), nodeA, slot)
	if err != nil {
		t.Fatal(err)
	}
	rec := func(name string, ok bool) BackendBinding {
		return BackendBinding{Name: name, Node: nodeA, VPCRef: vpcA, BackendAddress: addr, BackendPort: 8080,
			Bound: ok}
	}
	want := []BackendBinding{rec("b-bound", true), rec("b-deleting", false), rec("b-none", false),
		rec("b-source", false), rec("b-stale", false)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BackendBindings = %+v\nwant %+v", got, want)
	}
	if got, err := (Kube{Reader: c, Namespace: gwNS}).BackendBindings(context.Background(), nodeA, slot); err != nil ||
		len(got) != 0 {
		t.Fatalf("BackendBindings with no gateway namespace = %+v, %v; want none", got, err)
	}
}

// TestVPCOf checks the scope each watched change requeues: a binding's
// vpcRef, whose backend destinations it resolves, including from a
// tombstone.
func TestVPCOf(t *testing.T) {
	binding := &bgpv1alpha1.ServiceVIPBinding{Spec: bgpv1alpha1.ServiceVIPBindingSpec{VPCRef: vpcA}}
	for name, tc := range map[string]struct {
		obj  any
		want string
	}{
		"binding":        {binding, vpcA},
		"tombstone":      {toolscache.DeletedFinalStateUnknown{Obj: binding}, vpcA},
		"vpc attachment": {&cloudv1alpha1.VPCAttachment{Status: cloudv1alpha1.VPCAttachmentStatus{VPC: vpcA}}, vpcA},
		"router":         {&bgpv1alpha1.BGPRouter{}, ""},
	} {
		if got := vpcOf(tc.obj); got != tc.want {
			t.Errorf("%s: vpcOf = %q, want %q", name, got, tc.want)
		}
	}
}
