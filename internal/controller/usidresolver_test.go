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

	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

func TestBackendSIDIndex_ResolvesMatchingPrefix(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv := newBackendFixtures()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv).Build()

	idx, err := buildBackendSIDIndex(context.Background(), fakeClient, testNamespace)
	if err != nil {
		t.Fatalf("buildBackendSIDIndex: %v", err)
	}

	got, err := idx.resolveUSID(netip.MustParseAddr(testBackendAddr))
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
	router, adv := newBackendFixtures()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv).Build()

	idx, err := buildBackendSIDIndex(context.Background(), fakeClient, testNamespace)
	if err != nil {
		t.Fatalf("buildBackendSIDIndex: %v", err)
	}

	if _, err := idx.resolveUSID(netip.MustParseAddr("192.0.2.1")); err == nil {
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
	router, _ := newBackendFixtures()
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

	if _, err := idx.resolveUSID(netip.MustParseAddr(testBackendAddr)); err == nil {
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
			RouterID:  "1.1.1.2",
			Roles:     []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
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
	if _, err := idx.resolveUSID(netip.MustParseAddr(testBackendAddr)); err == nil {
		t.Fatal("resolveUSID: expected error since the matching router has no SRv6Locator/NodeID")
	}
}
