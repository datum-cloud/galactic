// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestGatewayHealthFailClosedIPv4StaysLoaded: a FailClosed rule's IPv4 VIP
// stays loaded, unadvertised, while no backend has a current Healthy result,
// so galactic-router keeps writing the IPv4 bindings whose health results
// would let it serve (ipv4LoadedOnSomeNode). It is advertised once a backend
// reports Healthy, and withdrawn but kept loaded once none does.
func TestGatewayHealthFailClosedIPv4StaysLoaded(t *testing.T) {
	rule := newTestRule(testRuleName, "vpc-1", testVIP4)
	rule.Spec.HealthCheck = &bgpv1alpha1.NetworkServiceHealthCheck{
		IntervalSeconds: 5, TimeoutSeconds: 2, UnhealthyThreshold: 3, HealthyThreshold: 3,
		FailurePolicy: bgpv1alpha1.NetworkServiceHealthFailClosed,
	}
	acceptRule(rule)
	attachment := newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4)
	attachment.UID = testGatewayHealthUID
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	c, engine, r := reconcileHealthGateway(t, true,
		newTestRouter(), backendRouter, backendAdv, backendVRF, attachment, rule)
	r.IPv4VIPs = true

	check := func(stage, wantReason string, wantAdvert bool) {
		t.Helper()
		runGatewayPass(t, r)
		runGatewayPass(t, r)
		engine.mu.Lock()
		desired := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]
		engine.mu.Unlock()
		if !slices.Contains(desired.VIPAddresses, netip.MustParseAddr(testVIP4)) ||
			!slices.Equal(backendAddrs(desired.IPv4Backends), []string{testBackendAddr}) {
			t.Errorf("%s: IPv4 VIP not loaded over %s: VIPs %v, backends %v",
				stage, testBackendAddr, desired.VIPAddresses, backendAddrs(desired.IPv4Backends))
		}
		if _, ok := advertisedPrefixes(t, c, testIPv4AdvName); ok != wantAdvert {
			t.Errorf("%s: -v4 advertised = %v, want %v", stage, ok, wantAdvert)
		}
		got := &bgpv1alpha1.NetworkService{}
		if err := c.Get(context.Background(), testRuleKey(testRuleName), got); err != nil {
			t.Fatal(err)
		}
		cond := meta.FindStatusCondition(got.Status.Conditions, ipv4ServedConditionType(testNodeGWA))
		if cond == nil || cond.Reason != wantReason {
			t.Errorf("%s: IPv4Served = %+v, want reason %s", stage, cond, wantReason)
		}
		if !ipv4LoadedOnSomeNode(got) {
			t.Errorf("%s: galactic-router would not write the IPv4 bindings", stage)
		}
		programmed := meta.FindStatusCondition(got.Status.Conditions, programmedConditionType(testNodeGWA))
		if programmed == nil || programmed.Status != metav1.ConditionTrue {
			t.Errorf("%s: Programmed = %+v, want True", stage, programmed)
		}
	}
	bindingKey := client.ObjectKeyFromObject(newIPv4Binding(rule, testBackendAddr, metav1.ConditionTrue, "Bound"))
	setHealth := func(state bgpv1alpha1.BackendHealthState) {
		t.Helper()
		b := &bgpv1alpha1.ServiceVIPBinding{}
		if err := c.Get(context.Background(), bindingKey, b); err != nil {
			t.Fatal(err)
		}
		b.Status.Health = decision(state)
		b.Status.Health.ObservedGeneration = rule.Generation
		b.Status.Health.LastProbeTime = metav1.Now()
		if err := c.Status().Update(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}

	check("no binding yet", reasonIPv4NoHealthyBackends, false)

	binding := newIPv4Binding(rule, testBackendAddr, metav1.ConditionTrue, "Bound")
	status := binding.Status
	if err := c.Create(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	binding.Status = status
	if err := c.Status().Update(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	check("Bound, no health result", reasonIPv4NoHealthyBackends, false)

	setHealth(bgpv1alpha1.BackendHealthUnhealthy)
	check("Bound and Unhealthy", reasonIPv4NoHealthyBackends, false)
	if cond := programmedFor(t, c); cond.Reason != reasonNoHealthyBackends {
		t.Errorf("Programmed reason = %s, want %s", cond.Reason, reasonNoHealthyBackends)
	}

	setHealth(bgpv1alpha1.BackendHealthHealthy)
	check("Bound and Healthy", reasonIPv4Advertised, true)

	setHealth(bgpv1alpha1.BackendHealthUnhealthy)
	check("Unhealthy again", reasonIPv4NoHealthyBackends, false)
}

// TestNetworkServiceBindingReconciler_IPv4BindingsWhileNoHealthyBackends: a
// gateway node that keeps a FailClosed rule's IPv4 VIP loaded, unadvertised,
// because no backend is Healthy yet still gets the IPv4 bindings, whose
// health results are what let the VIP serve.
func TestNetworkServiceBindingReconciler_IPv4BindingsWhileNoHealthyBackends(t *testing.T) {
	rule := newBindingTestRule()
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
		Type: ipv4ServedConditionType(testNodeGWA), Status: metav1.ConditionFalse, Reason: reasonIPv4NoHealthyBackends,
	})
	r, c := newBindingWriter(t, rule, newBackendAttachment(testVPCRef, testBackendAddr))
	reconcileBindings(t, r)
	got := bindingsByVIP(t, c, testRuleName)[testVIP4]
	if len(got) != 1 || got[0].Spec.BackendAddress != testBackendAddr {
		t.Errorf("IPv4 bindings = %+v, want one to %s", got, testBackendAddr)
	}
}
