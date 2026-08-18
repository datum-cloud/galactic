// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/crdnames"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Shared fixture identifiers for internal/controller's NetworkGateway/
// NetworkRule tests (this file, networkgateway_controller_test.go, and
// usidresolver_test.go).
const (
	testNamespace  = "ns"
	testNodeGWA    = "gw-a"
	testNodeGWB    = "gw-b"
	testRouterName = "router-a"
	testRuleName   = "rule-1"
	// testRuleAdvV4 is node-qualified by testNodeGWA -- see
	// NetworkGatewayReconciler.applyBGPAdvertisements's doc comment for why
	// every gateway node's own BGPAdvertisement name must include its node
	// name.
	testRuleAdvV4 = testRuleName + "-" + testNodeGWA + "-v4"
	testVIP       = "203.0.113.5"
	testVIPPrefix = testVIP + "/32"

	// testBackendAddr is the default backend address newTestRule uses.
	// testBackendRouterName/testBackendPrefix/testBackendVRFID describe the
	// BGPRouter/BGPAdvertisement newBackendFixtures returns, which resolves
	// it to a real SRv6 uSID — required for buildDesiredRule to succeed
	// (design plan decision #5; see usidresolver.go).
	testBackendAddr       = "10.0.0.1"
	testBackendPrefix     = "10.0.0.0/24"
	testBackendRouterName = "backend-router"
	testBackendLocator    = "2001:db8:ff01::/48"
	testBackendNodeID     = 7
	testBackendVRFID      = 100
	testComputeNodeName   = "compute-node-1"

	// testTargetRefKind is the TargetRef.Kind used by every fixture in
	// this test package -- extracted to a constant per goconst.
	testTargetRefKind = "Node"

	// testBackendRouterID and testRouteTargetValue are shared placeholder
	// values for BGPRouter.Spec.RouterID / BGPVRFInstance route targets
	// across this file's and usidresolver_test.go's fixtures -- extracted
	// to constants per goconst.
	testBackendRouterID  = "1.1.1.2"
	testRouteTargetValue = "65000:1"
)

func newRuleTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return scheme
}

func newTestGateway(node string) *bgpv1alpha1.NetworkGateway {
	return &bgpv1alpha1.NetworkGateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: node},
		Spec:       bgpv1alpha1.NetworkGatewaySpec{TargetRef: bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: node}},
	}
}

func newTestRule(name, vpcRef string, vips ...string) *bgpv1alpha1.NetworkRule {
	return &bgpv1alpha1.NetworkRule{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
		Spec: bgpv1alpha1.NetworkRuleSpec{
			VPCRef:           vpcRef,
			VPCAttachmentRef: "attach-1",
			VIPAddresses:     vips,
			Protocol:         bgpv1alpha1.NetworkRuleProtocolTCP,
			Port:             443,
			Backends: []bgpv1alpha1.NetworkRuleBackend{
				{Address: testBackendAddr, Port: 8443},
			},
		},
	}
}

// newBackendFixtures returns the BGPRouter/BGPAdvertisement/BGPVRFInstance
// triple that resolves testBackendAddr (newTestRule's default backend) to a
// real SRv6 uSID via usidresolver.go's containment-plus-tenant-ownership
// matching — without these, every rule newTestRule builds for vpcRef fails
// buildDesiredRule and is silently excluded from desired state.
//
// The BGPVRFInstance is what verifyTenantOwnership checks a candidate
// BGPAdvertisement against: its name is crdnames.BGPVRFInstanceName(vpcRef,
// testComputeNodeName), the exact deterministic name galactic-bgp would
// have written for this VPC on this node, and its VRFID must equal the
// advertisement's own VRFID for the match to be trusted. Two calls with
// different vpcRef values produce independently-named advertisements and
// VRF instances (crdnames.BGPAdvertisementName includes vpcRef), so callers
// resolving more than one VPC in the same fake client never collide.
func newBackendFixtures(
	vpcRef string,
) (*bgpv1alpha1.BGPRouter, *bgpv1alpha1.BGPAdvertisement, *bgpv1alpha1.BGPVRFInstance) {
	vrfID := int32(testBackendVRFID)
	function := bgpv1alpha1.SRv6FunctionEndDT46
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testBackendRouterName},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: testComputeNodeName},
			LocalASN:    65000,
			RouterID:    testBackendRouterID,
			Roles:       []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			SRv6Locator: testBackendLocator,
			NodeID:      testBackendNodeID,
		},
	}
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: crdnames.BGPAdvertisementName(vpcRef, "attach-1")},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testBackendRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testBackendPrefix},
			VRFID:         &vrfID,
			Function:      &function,
		},
	}
	vrfInstanceName := crdnames.BGPVRFInstanceName(vpcRef, testComputeNodeName)
	vrfInstance := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: vrfInstanceName},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: testBackendRouterName}},
			VRFID:              vrfID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTargetValue}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTargetValue}},
		},
	}
	return router, adv, vrfInstance
}

func testRuleKey(name string) types.NamespacedName {
	return types.NamespacedName{Namespace: testNamespace, Name: name}
}

func TestNetworkRuleReconciler_SetsFinalizerAndAccepted(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	gwB := newTestGateway(testNodeGWB)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, gwB, rule).
		Build()

	r := &NetworkRuleReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	req := ctrl.Request{NamespacedName: testRuleKey(testRuleName)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	got := &bgpv1alpha1.NetworkRule{}
	if err := fakeClient.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if !controllerutil.ContainsFinalizer(got, networkRuleFinalizer) {
		t.Fatal("finalizer was not added")
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		t.Fatal("Accepted condition was not set to True once gateway nodes exist")
	}

	// Reconcile again after the gateway pool changes -- under DSR's anycast
	// model there is no primary/secondary assignment to flip, but Accepted
	// must stay True and reconciling must remain a no-op/idempotent.
	gwC := newTestGateway("gw-c")
	if err := fakeClient.Create(context.Background(), gwC); err != nil {
		t.Fatalf("create gw-c: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("second Reconcile: unexpected error: %v", err)
	}
	got2 := &bgpv1alpha1.NetworkRule{}
	if err := fakeClient.Get(context.Background(), req.NamespacedName, got2); err != nil {
		t.Fatalf("get rule after second reconcile: %v", err)
	}
	if !meta.IsStatusConditionTrue(got2.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		t.Fatal("Accepted condition did not remain True across a second reconcile")
	}
}

// TestNetworkRuleReconciler_UpdateAcceptedCondition_FalseWithNoGatewayNodes
// covers the converse of the above directly against updateAcceptedCondition:
// with no NetworkGateway registered in the namespace, Accepted must be
// False, not merely absent, so NetworkGatewayReconciler's
// IsStatusConditionTrue gate and any status consumer both see an explicit,
// not-yet-eligible signal.
//
// This bypasses Reconcile/isGatewayNode deliberately: isGatewayNode derives
// "is this node a gateway" from the very same NetworkGateway list
// updateAcceptedCondition's own zero-nodes branch checks, so with zero
// NetworkGateways registered anywhere, Reconcile would never reach
// updateAcceptedCondition in the first place -- the branch under test here
// is exercised directly, the way it would be reached by a genuine
// list-changed-between-calls race rather than through the reconciler's
// normal entrypoint.
func TestNetworkRuleReconciler_UpdateAcceptedCondition_FalseWithNoGatewayNodes(t *testing.T) {
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}).
		WithObjects(rule).
		Build()

	r := &NetworkRuleReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	if err := r.updateAcceptedCondition(context.Background(), rule); err != nil {
		t.Fatalf("updateAcceptedCondition: unexpected error: %v", err)
	}

	got := &bgpv1alpha1.NetworkRule{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleName), got); err != nil {
		t.Fatalf("get rule: %v", err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted)
	if cond == nil {
		t.Fatal("Accepted condition was not set at all")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Fatalf("Accepted condition status = %v, want False", cond.Status)
	}
}

// TestNetworkRuleReconciler_GatewayAppearanceRequeuesParkedRule covers the
// full recovery path for a rule created before any gateway node registered:
// it parks at Accepted=False, and the NetworkGateway watch's mapper
// (gatewayToRuleRequests) enqueues it as soon as a gateway registers, at
// which point the ordinary reconcile flips it to Accepted=True. Without that
// watch the rule waits for the informer's periodic resync (#367).
func TestNetworkRuleReconciler_GatewayAppearanceRequeuesParkedRule(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}).
		WithObjects(rule).
		Build()

	r := &NetworkRuleReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}

	// No NetworkGateway exists yet, so this is the zero-nodes branch (see
	// TestNetworkRuleReconciler_UpdateAcceptedCondition_FalseWithNoGatewayNodes
	// for why it is reached directly rather than through Reconcile).
	if err := r.updateAcceptedCondition(ctx, rule); err != nil {
		t.Fatalf("updateAcceptedCondition: unexpected error: %v", err)
	}
	parked := &bgpv1alpha1.NetworkRule{}
	if err := fakeClient.Get(ctx, testRuleKey(testRuleName), parked); err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if meta.IsStatusConditionTrue(parked.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		t.Fatal("Accepted must not be True with no gateway nodes registered")
	}

	// A gateway node registers: the mapper must enqueue the parked rule.
	gwA := newTestGateway(testNodeGWA)
	if err := fakeClient.Create(ctx, gwA); err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	reqs := gatewayToRuleRequests(ctx, fakeClient, gwA)
	want := testRuleKey(testRuleName)
	found := false
	for _, req := range reqs {
		if req.NamespacedName == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("gatewayToRuleRequests(%s) = %v, want a request for %s", gwA.Name, reqs, want)
	}

	// Non-NetworkGateway objects must map to nothing.
	if got := gatewayToRuleRequests(ctx, fakeClient, rule); got != nil {
		t.Fatalf("gatewayToRuleRequests on a non-NetworkGateway = %v, want nil", got)
	}

	// Reconciling that enqueued request must unpark the rule.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: want}); err != nil {
		t.Fatalf("Reconcile after gateway registration: unexpected error: %v", err)
	}
	got := &bgpv1alpha1.NetworkRule{}
	if err := fakeClient.Get(ctx, want, got); err != nil {
		t.Fatalf("get rule after requeue: %v", err)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		t.Fatal("Accepted was not flipped to True after a gateway node registered")
	}
}

func TestNetworkRuleReconciler_NoOpOnNonGatewayNode(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, rule).
		Build()

	// compute-node-1 is not a registered NetworkGateway target.
	r := &NetworkRuleReconciler{Client: fakeClient, Scheme: scheme, NodeName: testComputeNodeName}
	req := ctrl.Request{NamespacedName: testRuleKey(testRuleName)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	got := &bgpv1alpha1.NetworkRule{}
	if err := fakeClient.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, bgpv1alpha1.ConditionTypeAccepted) {
		t.Fatal("non-gateway node reconciler must not update the Accepted condition")
	}
	if controllerutil.ContainsFinalizer(got, networkRuleFinalizer) {
		t.Fatal("non-gateway node reconciler must not add the finalizer")
	}
}

func TestNetworkRuleReconciler_TeardownOrder_WithdrawsBGPBeforeRemovingFinalizer(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	rule.Finalizers = []string{networkRuleFinalizer}
	now := metav1.Now()
	rule.DeletionTimestamp = &now

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testRuleAdvV4,
			Labels:    map[string]string{networkRuleLabel: testRuleName},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testVIPPrefix},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, rule, adv).
		Build()

	r := &NetworkRuleReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	req := ctrl.Request{NamespacedName: testRuleKey(testRuleName)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	// BGPAdvertisement must have been deleted (step 1: BGP withdrawal).
	gotAdv := &bgpv1alpha1.BGPAdvertisement{}
	err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), gotAdv)
	if err == nil {
		t.Fatal("BGPAdvertisement was not withdrawn on NetworkRule deletion")
	}

	// The NetworkRule itself should now be gone (finalizer removed and no
	// other finalizers/owners keeping it around in the fake client).
	gotRule := &bgpv1alpha1.NetworkRule{}
	err = fakeClient.Get(context.Background(), req.NamespacedName, gotRule)
	if err == nil {
		t.Fatal("NetworkRule was not removed after finalizer teardown completed")
	}
}

// TestNetworkRuleReconciler_TeardownWithdrawsAdvertisementForDepartedNode is
// the regression test for issue #367: an advertisement created for a node
// that has since left the namespace (no corresponding NetworkGateway object
// exists any more) must still be withdrawn on rule teardown. Discovery by
// networkRuleLabel doesn't depend on the namespace's current gateway-node
// membership the way reconstructing the name from gatewayNodeNames did.
func TestNetworkRuleReconciler_TeardownWithdrawsAdvertisementForDepartedNode(t *testing.T) {
	scheme := newRuleTestScheme(t)
	// Only gw-a is registered now; the advertisement below was created for
	// gw-b, which has since left.
	gwA := newTestGateway(testNodeGWA)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	rule.Finalizers = []string{networkRuleFinalizer}
	now := metav1.Now()
	rule.DeletionTimestamp = &now

	departedNodeAdvName := testRuleName + "-" + testNodeGWB + "-v4"
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      departedNodeAdvName,
			Labels:    map[string]string{networkRuleLabel: testRuleName},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testVIPPrefix},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, rule, adv).
		Build()

	r := &NetworkRuleReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	req := ctrl.Request{NamespacedName: testRuleKey(testRuleName)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	gotAdv := &bgpv1alpha1.BGPAdvertisement{}
	err := fakeClient.Get(context.Background(), testRuleKey(departedNodeAdvName), gotAdv)
	if err == nil {
		t.Fatal("BGPAdvertisement for a departed node was not withdrawn on NetworkRule deletion")
	}
}

// TestNetworkRuleReconciler_TeardownIgnoresAdvertisementForDifferentRule
// guards against a label selector broad enough to sweep up another rule's
// advertisement in the same namespace.
func TestNetworkRuleReconciler_TeardownIgnoresAdvertisementForDifferentRule(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	rule.Finalizers = []string{networkRuleFinalizer}
	now := metav1.Now()
	rule.DeletionTimestamp = &now

	const otherRuleName = "rule-2"
	otherAdvName := otherRuleName + "-" + testNodeGWA + "-v4"
	otherAdv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      otherAdvName,
			Labels:    map[string]string{networkRuleLabel: otherRuleName},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testVIPPrefix},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, rule, otherAdv).
		Build()

	r := &NetworkRuleReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	req := ctrl.Request{NamespacedName: testRuleKey(testRuleName)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	gotAdv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(context.Background(), testRuleKey(otherAdvName), gotAdv); err != nil {
		t.Fatalf("another rule's BGPAdvertisement was incorrectly withdrawn: %v", err)
	}
}

func TestNetworkRuleReconciler_TeardownIsIdempotentWhenAdvertisementAlreadyGone(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	rule.Finalizers = []string{networkRuleFinalizer}
	now := metav1.Now()
	rule.DeletionTimestamp = &now

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, rule).
		Build()

	r := &NetworkRuleReconciler{Client: fakeClient, Scheme: scheme, NodeName: testNodeGWA}
	req := ctrl.Request{NamespacedName: testRuleKey(testRuleName)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error when no BGPAdvertisement exists: %v", err)
	}
}
