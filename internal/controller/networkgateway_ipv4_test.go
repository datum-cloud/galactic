// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestNetworkGatewayReconciler_WithholdsIPv4VIPs covers the #705 stopgap: an
// IPv4 VIP is never loaded or advertised, a "-v4" advertisement an earlier
// release made is withdrawn, the rule's IPv6 VIP keeps serving, and the
// node's IPv4Served condition says why the IPv4 address does not work.
func TestNetworkGatewayReconciler_WithholdsIPv4VIPs(t *testing.T) {
	tests := []struct {
		name           string
		vips           []string
		wantLoaded     bool
		wantProgrammed metav1.ConditionStatus
		wantReason     string
	}{
		{
			name:           "dual-stack rule serves its IPv6 VIP",
			vips:           []string{testVIP, testVIP4},
			wantLoaded:     true,
			wantProgrammed: metav1.ConditionTrue,
			wantReason:     reasonProgrammed,
		},
		{
			name:           "IPv4-only rule loads nothing",
			vips:           []string{testVIP4},
			wantProgrammed: metav1.ConditionFalse,
			wantReason:     reasonNoServedVIP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newRuleTestScheme(t)
			backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
			rule := newTestRule(testRuleName, "vpc-1", tt.vips...)
			acceptRule(rule)
			staleV4 := newNodeAdvertisement(testRuleName, testNodeGWA, "v4")
			otherNodeV4 := newNodeAdvertisement(testRuleName, testNodeGWB, "v4")

			fakeClient := newIndexedClientBuilder(scheme).
				WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{}).
				WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
					newBackendAttachment("vpc-1"), rule, staleV4, otherNodeV4).
				Build()
			ctx := context.Background()

			engine := newFakeGatewayEngine()
			r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			desired, loaded := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]
			if loaded != tt.wantLoaded {
				t.Fatalf("rule loaded = %v, want %v", loaded, tt.wantLoaded)
			}
			if loaded && !slices.Equal(desired.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) {
				t.Errorf("loaded VIPs = %v, want only %s", desired.VIPAddresses, testVIP)
			}

			err := fakeClient.Get(ctx, testRuleKey(staleV4.Name), &bgpv1alpha1.BGPAdvertisement{})
			if !apierrors.IsNotFound(err) {
				t.Errorf("this node's -v4 advertisement: err = %v, want NotFound", err)
			}
			if err := fakeClient.Get(ctx, testRuleKey(otherNodeV4.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
				t.Errorf("node %s's -v4 advertisement was removed by node %s: %v", testNodeGWB, testNodeGWA, err)
			}
			err = fakeClient.Get(ctx, testRuleKey(testRuleAdv), &bgpv1alpha1.BGPAdvertisement{})
			switch {
			case tt.wantLoaded && err != nil:
				t.Errorf("-v6 advertisement: %v", err)
			case !tt.wantLoaded && !apierrors.IsNotFound(err):
				t.Errorf("-v6 advertisement: err = %v, want NotFound for a rule with no IPv6 VIP", err)
			}

			got := &bgpv1alpha1.NetworkService{}
			if err := fakeClient.Get(ctx, testRuleKey(testRuleName), got); err != nil {
				t.Fatalf("get NetworkService: %v", err)
			}
			programmed := meta.FindStatusCondition(got.Status.Conditions, programmedConditionType(testNodeGWA))
			if programmed == nil || programmed.Status != tt.wantProgrammed || programmed.Reason != tt.wantReason {
				t.Errorf("Programmed = %+v, want %s/%s", programmed, tt.wantProgrammed, tt.wantReason)
			}
			ipv4 := meta.FindStatusCondition(got.Status.Conditions, ipv4ServedConditionType(testNodeGWA))
			if ipv4 == nil || ipv4.Status != metav1.ConditionFalse || ipv4.Reason != reasonIPv4Unsupported {
				t.Errorf("IPv4Served = %+v, want False/%s", ipv4, reasonIPv4Unsupported)
			}
			if ipv4 != nil && ipv4.ObservedGeneration != got.Generation {
				t.Errorf("IPv4Served observedGeneration = %d, want %d", ipv4.ObservedGeneration, got.Generation)
			}
		})
	}
}

// TestNetworkGatewayReconciler_RemovesIPv4ServedWithoutIPv4VIP covers a rule
// whose IPv4 VIP was removed: this node drops its own IPv4Served condition
// and leaves another node's alone.
func TestNetworkGatewayReconciler_RemovesIPv4ServedWithoutIPv4VIP(t *testing.T) {
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)
	for _, node := range []string{testNodeGWA, testNodeGWB} {
		meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
			Type: ipv4ServedConditionType(node), Status: metav1.ConditionFalse, Reason: reasonIPv4Unsupported,
		})
	}

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
			newBackendAttachment("vpc-1"), rule).
		Build()

	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &bgpv1alpha1.NetworkService{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleName), got); err != nil {
		t.Fatalf("get NetworkService: %v", err)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, ipv4ServedConditionType(testNodeGWA)); c != nil {
		t.Errorf("node %s kept IPv4Served for a rule with no IPv4 VIP: %+v", testNodeGWA, c)
	}
	if meta.FindStatusCondition(got.Status.Conditions, ipv4ServedConditionType(testNodeGWB)) == nil {
		t.Errorf("node %s removed node %s's IPv4Served condition", testNodeGWA, testNodeGWB)
	}
}

// TestNetworkGatewayReconciler_ClearsDepartedNodeIPv4ServedCondition covers a
// departed gateway node: its IPv4Served condition goes with its Programmed
// condition.
func TestNetworkGatewayReconciler_ClearsDepartedNodeIPv4ServedCondition(t *testing.T) {
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	acceptRule(rule)
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
		Type: ipv4ServedConditionType(testNodeGWB), Status: metav1.ConditionFalse, Reason: reasonIPv4Unsupported,
	})

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{}).
		WithObjects(newTestGateway(testNodeGWA), rule).
		Build()

	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: testRuleKey(testNodeGWB)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &bgpv1alpha1.NetworkService{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleName), got); err != nil {
		t.Fatalf("get NetworkService: %v", err)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, ipv4ServedConditionType(testNodeGWB)); c != nil {
		t.Errorf("departed node %s's IPv4Served condition is still on the rule: %+v", testNodeGWB, c)
	}
}

// TestBuildDesiredRule_LeavesOutIPv4VIPs covers buildDesiredRule's VIP
// filter: IPv4 VIPs are dropped, a rule with nothing else fails with
// errNoServedVIP, and an address that does not parse still fails the rule
// as a spec error.
func TestBuildDesiredRule_LeavesOutIPv4VIPs(t *testing.T) {
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	idx := &backendSIDIndex{
		routers:      map[string]*bgpv1alpha1.BGPRouter{backendRouter.Name: backendRouter},
		advs:         []*bgpv1alpha1.BGPAdvertisement{backendAdv},
		vrfInstances: map[string]*bgpv1alpha1.BGPVRFInstance{backendVRF.Name: backendVRF},
	}
	attachments := []*cloudv1alpha1.VPCAttachment{newBackendAttachment("vpc-1")}

	dr, _, err := buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4, testVIP), attachments, idx, nil)
	if err != nil {
		t.Fatalf("dual-stack rule: %v", err)
	}
	if !slices.Equal(dr.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) {
		t.Errorf("dual-stack rule VIPs = %v, want only %s", dr.VIPAddresses, testVIP)
	}

	_, _, err = buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4, "198.51.100.7"), attachments, idx, nil)
	if !errors.Is(err, errNoServedVIP) {
		t.Errorf("IPv4-only rule: err = %v, want errNoServedVIP", err)
	}

	_, _, err = buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4, "not-an-ip"), attachments, idx, nil)
	if err == nil || errors.Is(err, errNoServedVIP) {
		t.Errorf("rule with an unparseable VIP: err = %v, want a parse error", err)
	}

	mapped := newTestRule(testRuleName, "vpc-1", testVIP, "::ffff:203.0.113.5")
	if !hasIPv4VIP(mapped) {
		t.Error("hasIPv4VIP missed an IPv4-mapped IPv6 VIP")
	}
	dr, _, err = buildDesiredRule(mapped, attachments, idx, nil)
	if err != nil {
		t.Fatalf("rule with an IPv4-mapped VIP: %v", err)
	}
	if !slices.Equal(dr.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) {
		t.Errorf("rule with an IPv4-mapped VIP loaded %v, want only %s", dr.VIPAddresses, testVIP)
	}
}

// TestDrainingOutcome_WithholdsIPv4VIPs covers a deleting rule whose route is
// still advertised: a dual-stack rule drains with its IPv6 VIP alone, and an
// IPv4-only rule, which this node never loaded, does not drain at all.
func TestDrainingOutcome_WithholdsIPv4VIPs(t *testing.T) {
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	idx := &backendSIDIndex{
		routers:      map[string]*bgpv1alpha1.BGPRouter{backendRouter.Name: backendRouter},
		advs:         []*bgpv1alpha1.BGPAdvertisement{backendAdv},
		vrfInstances: map[string]*bgpv1alpha1.BGPVRFInstance{backendVRF.Name: backendVRF},
	}
	attachments := []*cloudv1alpha1.VPCAttachment{newBackendAttachment("vpc-1")}

	tests := []struct {
		name         string
		vips         []string
		wantDraining bool
	}{
		{name: "dual-stack rule drains its IPv6 VIP", vips: []string{testVIP, testVIP4}, wantDraining: true},
		{name: "IPv4-only rule does not drain", vips: []string{testVIP4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newRuleTestScheme(t)
			rule := newTestRule(testRuleName, "vpc-1", tt.vips...)
			acceptRule(rule)
			rule.Finalizers = []string{networkRuleFinalizer}
			now := metav1.Now()
			rule.DeletionTimestamp = &now
			// Another node's route for the rule is still up, so the rule
			// would drain if this node had anything to keep loaded.
			stillAdvertised := newNodeAdvertisement(testRuleName, testNodeGWB, "v6")

			fakeClient := newIndexedClientBuilder(scheme).WithObjects(rule, stillAdvertised).Build()
			r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)

			o, draining, err := r.drainingOutcome(context.Background(), rule, attachments, idx, nil)
			if err != nil {
				t.Fatalf("drainingOutcome: %v", err)
			}
			if draining != tt.wantDraining {
				t.Fatalf("draining = %v, want %v", draining, tt.wantDraining)
			}
			if draining && !slices.Equal(o.desired.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) {
				t.Errorf("draining VIPs = %v, want only %s", o.desired.VIPAddresses, testVIP)
			}
		})
	}
}
