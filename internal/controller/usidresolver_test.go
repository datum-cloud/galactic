// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net/netip"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// testVPCRef is the tenant identity used by the single-VPC fixtures below.
// See TestBackendSIDIndex_TenantOwnershipDisambiguatesCollidingPrefixes for
// the case where two different VPCRef values are in play at once.
const testVPCRef = "vpc-1"

func TestBackendSIDIndex_ResolvesMatchingPrefix(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv, vrf).Build()

	idx, err := buildBackendSIDIndex(context.Background(), fakeClient, testNamespace)
	if err != nil {
		t.Fatalf("buildBackendSIDIndex: %v", err)
	}

	got, err := idx.resolveUSID(netip.MustParseAddr(testBackendAddr), testVPCRef)
	if err != nil {
		t.Fatalf("resolveUSID: %v", err)
	}

	want, err := srv6.ComputeSID(testBackendLocator, testBackendNodeID, testBackendVRFID, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatalf("srv6.ComputeSID: %v", err)
	}
	if got != want {
		t.Errorf("resolveUSID = %s, want %s", got, want)
	}
}

func TestBackendSIDIndex_NoMatchingPrefixIsError(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv, vrf).Build()

	idx, err := buildBackendSIDIndex(context.Background(), fakeClient, testNamespace)
	if err != nil {
		t.Fatalf("buildBackendSIDIndex: %v", err)
	}

	if _, err := idx.resolveUSID(netip.MustParseAddr("192.0.2.1"), testVPCRef); err == nil {
		t.Fatal("resolveUSID: expected error for an address with no matching BGPAdvertisement prefix")
	}
}

// TestBackendSIDIndex_ExcludesAdvertisementsWithoutVRFIDOrFunction verifies
// that an advertisement with no SRv6 VRFID/Function (e.g. a NetworkRule VIP
// preference advertisement, or a rule's own self-address advertisement --
// see NetworkGatewayReconciler.applyBGPAdvertisements/publishSelfAddress)
// is excluded from matching even if its prefix would otherwise contain the
// address, since it carries no SRv6 decap behavior of its own.
func TestBackendSIDIndex_ExcludesAdvertisementsWithoutVRFIDOrFunction(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, _, _ := newBackendFixtures(testVPCRef)
	plainAdv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "plain-adv"},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testBackendRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testBackendPrefix},
			// No VRFID/Function set.
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, plainAdv).Build()

	idx, err := buildBackendSIDIndex(context.Background(), fakeClient, testNamespace)
	if err != nil {
		t.Fatalf("buildBackendSIDIndex: %v", err)
	}
	if len(idx.advs) != 0 {
		t.Fatalf("advs = %d, want 0 (VRFID/Function-less advertisement must be excluded)", len(idx.advs))
	}

	if _, err := idx.resolveUSID(netip.MustParseAddr(testBackendAddr), testVPCRef); err == nil {
		t.Fatal("resolveUSID: expected error since the only matching advertisement has no VRFID/Function")
	}
}

// TestBackendSIDIndex_SkipsRouterWithoutSRv6Config verifies an advertisement
// whose RouterRef names a BGPRouter with no SRv6Locator/NodeID configured
// is skipped rather than causing srv6.ComputeSID to be called with empty
// values.
func TestBackendSIDIndex_SkipsRouterWithoutSRv6Config(t *testing.T) {
	scheme := newRuleTestScheme(t)
	vrfID := int32(testBackendVRFID)
	function := bgpv1alpha1.SRv6FunctionEndDT46
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testBackendRouterName},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: testComputeNodeName},
			LocalASN:  65000,
			RouterID:  testBackendRouterID,
			// No SRv6Locator/NodeID.
		},
	}
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "backend-adv"},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testBackendRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testBackendPrefix},
			VRFID:         &vrfID,
			Function:      &function,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv).Build()

	idx, err := buildBackendSIDIndex(context.Background(), fakeClient, testNamespace)
	if err != nil {
		t.Fatalf("buildBackendSIDIndex: %v", err)
	}
	if _, err := idx.resolveUSID(netip.MustParseAddr(testBackendAddr), testVPCRef); err == nil {
		t.Fatal("resolveUSID: expected error since the matching router has no SRv6Locator/NodeID")
	}
}

// TestBackendSIDIndex_TenantOwnershipDisambiguatesCollidingPrefixes is the
// regression test for the gap usidresolver.go's own doc comment used to
// flag: two tenants (here vpc-1 and vpc-2) each advertising the *same*
// backend prefix -- realistic for colliding ULA space across VPCs -- must
// resolve independently and correctly, never into each other's VRF, even
// though both candidate BGPAdvertisements pass prefix containment.
func TestBackendSIDIndex_TenantOwnershipDisambiguatesCollidingPrefixes(t *testing.T) {
	scheme := newRuleTestScheme(t)

	const (
		vpcA        = "vpc-1"
		vpcB        = "vpc-2"
		vpcAVRFID   = int32(100)
		vpcBVRFID   = int32(101)
		vpcALocator = "2001:db8:ff01::/48"
		vpcBLocator = "2001:db8:ff02::/48"
	)

	// Two tenants, two separate BGPRouters (distinct nodes), each
	// advertising the identical colliding prefix under its own VPC.
	routerA := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "router-vpc-a"},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: "node-a"},
			LocalASN:    65000,
			RouterID:    "1.1.1.1",
			SRv6Locator: vpcALocator,
			NodeID:      7,
		},
	}
	routerB := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "router-vpc-b"},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: "node-b"},
			LocalASN:    65000,
			RouterID:    testBackendRouterID,
			SRv6Locator: vpcBLocator,
			NodeID:      8,
		},
	}

	advA := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: crdnames.BGPAdvertisementName(vpcA, "attach-a", "node-a")},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: routerA.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testBackendPrefix}, // same prefix as vpc-b, on purpose
			VRFID:         ptr(vpcAVRFID),
			Function:      ptr(bgpv1alpha1.SRv6FunctionEndDT46),
		},
	}
	advB := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: crdnames.BGPAdvertisementName(vpcB, "attach-b", "node-b")},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: routerB.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testBackendPrefix}, // colliding ULA: identical to advA's
			VRFID:         ptr(vpcBVRFID),
			Function:      ptr(bgpv1alpha1.SRv6FunctionEndDT46),
		},
	}

	vrfA := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: crdnames.BGPVRFInstanceName(vpcA, "node-a")},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerA.Name}},
			VRFID:              vpcAVRFID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTargetValue}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTargetValue}},
		},
	}
	vrfB := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: crdnames.BGPVRFInstanceName(vpcB, "node-b")},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerB.Name}},
			VRFID:              vpcBVRFID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:2"}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:2"}},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(routerA, routerB, advA, advB, vrfA, vrfB).Build()

	idx, err := buildBackendSIDIndex(context.Background(), fakeClient, testNamespace)
	if err != nil {
		t.Fatalf("buildBackendSIDIndex: %v", err)
	}

	addr := netip.MustParseAddr(testBackendAddr) // falls within both advA's and advB's prefix

	gotA, err := idx.resolveUSID(addr, vpcA)
	if err != nil {
		t.Fatalf("resolveUSID(vpc-1): %v", err)
	}
	wantA, err := srv6.ComputeSID(vpcALocator, routerA.Spec.NodeID, vpcAVRFID, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatalf("srv6.ComputeSID(vpc-1): %v", err)
	}
	if gotA != wantA {
		t.Errorf("resolveUSID(vpc-1) = %s, want %s (vpc-1's own SID, not vpc-2's)", gotA, wantA)
	}

	gotB, err := idx.resolveUSID(addr, vpcB)
	if err != nil {
		t.Fatalf("resolveUSID(vpc-2): %v", err)
	}
	wantB, err := srv6.ComputeSID(vpcBLocator, routerB.Spec.NodeID, vpcBVRFID, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatalf("srv6.ComputeSID(vpc-2): %v", err)
	}
	if gotB != wantB {
		t.Errorf("resolveUSID(vpc-2) = %s, want %s (vpc-2's own SID, not vpc-1's)", gotB, wantB)
	}

	if gotA == gotB {
		t.Fatal("resolveUSID(vpc-1) and resolveUSID(vpc-2) must never agree for a colliding backend address")
	}
}

// TestBackendSIDIndex_UnrelatedTenantVRFIsNotTrusted verifies that a
// BGPVRFInstance existing for some *other* VPC on the same node doesn't
// vouch for an advertisement it doesn't actually own -- resolveUSID must
// still fail rather than fall back to whatever it can find.
func TestBackendSIDIndex_UnrelatedTenantVRFIsNotTrusted(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, _ := newBackendFixtures(testVPCRef) // note: vrf instance for testVPCRef intentionally omitted
	otherVRFName := crdnames.BGPVRFInstanceName("vpc-other", testComputeNodeName)
	otherVRF := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: otherVRFName},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: testBackendRouterName}},
			VRFID:              testBackendVRFID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:9"}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:9"}},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv, otherVRF).Build()

	idx, err := buildBackendSIDIndex(context.Background(), fakeClient, testNamespace)
	if err != nil {
		t.Fatalf("buildBackendSIDIndex: %v", err)
	}
	if _, err := idx.resolveUSID(netip.MustParseAddr(testBackendAddr), testVPCRef); err == nil {
		t.Fatal("resolveUSID: expected error -- no BGPVRFInstance named for testVPCRef exists, " +
			"a same-node VRF instance belonging to a different VPC must not be trusted")
	}
}

func ptr[T any](v T) *T { return &v }
