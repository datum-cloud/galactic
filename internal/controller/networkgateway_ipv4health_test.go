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

// newFailClosedIPv4Gateway returns a testNodeGWA reconciler with IPv4VIPs and
// backend health on, over a FailClosed rule on vips with one dual-stack backend
// attachment, plus extra objects.
func newFailClosedIPv4Gateway(
	t *testing.T, vips []string, extra ...client.Object,
) (*bgpv1alpha1.NetworkService, client.Client, *fakeGatewayEngine, *NetworkGatewayReconciler) {
	t.Helper()
	rule := newTestRule(testRuleName, "vpc-1", vips...)
	rule.Spec.HealthCheck = &bgpv1alpha1.NetworkServiceHealthCheck{
		IntervalSeconds: 5, TimeoutSeconds: 2, UnhealthyThreshold: 3, HealthyThreshold: 3,
		FailurePolicy: bgpv1alpha1.NetworkServiceHealthFailClosed,
	}
	acceptRule(rule)
	attachment := newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4)
	attachment.UID = testGatewayHealthUID
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	objs := append([]client.Object{newTestRouter(), backendRouter, backendAdv, backendVRF, attachment, rule},
		extra...)
	c, engine, r := reconcileHealthGateway(t, true, objs...)
	r.IPv4VIPs = true
	return rule, c, engine, r
}

// freshDecision returns a decision of state for rule's current generation,
// probed now.
func freshDecision(
	rule *bgpv1alpha1.NetworkService, state bgpv1alpha1.BackendHealthState,
) *bgpv1alpha1.ServiceVIPBindingHealth {
	h := decision(state)
	h.ObservedGeneration = rule.Generation
	h.LastProbeTime = metav1.Now()
	return h
}

// TestGatewayHealthFailClosedIPv4WaitsForHealth: while no backend of a
// FailClosed rule's IPv4 VIP has a current Healthy result, the VIP is left
// out of the engine and withdrawn, but IPv4Served reports NoHealthyBackends,
// which galactic-router counts as served (ipv4LoadedOnSomeNode), so it keeps
// writing the IPv4 bindings whose health results let the VIP serve. The VIP
// loads and is advertised once a backend reports Healthy, and is left out
// again, still counted as served, once none does.
func TestGatewayHealthFailClosedIPv4WaitsForHealth(t *testing.T) {
	rule, c, engine, r := newFailClosedIPv4Gateway(t, []string{testVIP4})

	check := func(stage string, wantServing bool) {
		t.Helper()
		runGatewayPass(t, r)
		runGatewayPass(t, r)
		engine.mu.Lock()
		desired, loaded := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]
		engine.mu.Unlock()
		v4Loaded := loaded && slices.Contains(desired.VIPAddresses, netip.MustParseAddr(testVIP4))
		if v4Loaded != wantServing {
			t.Errorf("%s: IPv4 VIP loaded = %v, want %v (backends %v)",
				stage, v4Loaded, wantServing, backendAddrs(desired.IPv4Backends))
		}
		if _, ok := advertisedPrefixes(t, c, testIPv4AdvName); ok != wantServing {
			t.Errorf("%s: -v4 advertised = %v, want %v", stage, ok, wantServing)
		}
		got := &bgpv1alpha1.NetworkService{}
		if err := c.Get(context.Background(), testRuleKey(testRuleName), got); err != nil {
			t.Fatal(err)
		}
		wantReason, wantProgrammed := reasonIPv4NoHealthyBackends, metav1.ConditionFalse
		if wantServing {
			wantReason, wantProgrammed = reasonIPv4Advertised, metav1.ConditionTrue
		}
		if cond := meta.FindStatusCondition(got.Status.Conditions, ipv4ServedConditionType(testNodeGWA)); cond == nil ||
			cond.Reason != wantReason {
			t.Errorf("%s: IPv4Served = %+v, want reason %s", stage, cond, wantReason)
		}
		if !ipv4LoadedOnSomeNode(got) {
			t.Errorf("%s: galactic-router would not write the IPv4 bindings", stage)
		}
		programmed := meta.FindStatusCondition(got.Status.Conditions, programmedConditionType(testNodeGWA))
		if programmed == nil || programmed.Status != wantProgrammed ||
			(!wantServing && programmed.Reason != reasonNoHealthyBackends) {
			t.Errorf("%s: Programmed = %+v, want %s", stage, programmed, wantProgrammed)
		}
		advertised := meta.FindStatusCondition(got.Status.Conditions, advertisedConditionType(testNodeGWA))
		if !wantServing && (advertised == nil || advertised.Status != metav1.ConditionFalse) {
			t.Errorf("%s: Advertised = %+v, want False", stage, advertised)
		}
	}
	bindingKey := client.ObjectKeyFromObject(newIPv4Binding(rule, testBackendAddr, metav1.ConditionTrue, "Bound"))
	setHealth := func(state bgpv1alpha1.BackendHealthState) {
		t.Helper()
		b := &bgpv1alpha1.ServiceVIPBinding{}
		if err := c.Get(context.Background(), bindingKey, b); err != nil {
			t.Fatal(err)
		}
		b.Status.Health = freshDecision(rule, state)
		if err := c.Status().Update(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}

	check("no binding yet", false)

	binding := newIPv4Binding(rule, testBackendAddr, metav1.ConditionTrue, "Bound")
	status := binding.Status
	if err := c.Create(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	binding.Status = status
	if err := c.Status().Update(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	check("Bound, no health result", false)

	setHealth(bgpv1alpha1.BackendHealthUnhealthy)
	check("Bound and Unhealthy", false)

	setHealth(bgpv1alpha1.BackendHealthHealthy)
	check("Bound and Healthy", true)

	setHealth(bgpv1alpha1.BackendHealthUnhealthy)
	check("Unhealthy again", false)
}

// TestGatewayHealthFailClosedDualStackIPv4WaitsForHealth: a dual-stack
// FailClosed rule whose IPv6 backend is Healthy serves its IPv6 VIP while its
// IPv4 VIP, with no Healthy result yet, is left out and reported
// NoHealthyBackends, so galactic-router writes its IPv4 bindings.
func TestGatewayHealthFailClosedDualStackIPv4WaitsForHealth(t *testing.T) {
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	rule.Spec.HealthCheck = &bgpv1alpha1.NetworkServiceHealthCheck{}
	ipv6 := healthBinding(rule, testBackendAddr, freshDecision(rule, bgpv1alpha1.BackendHealthHealthy))
	rule, c, engine, r := newFailClosedIPv4Gateway(t, []string{testVIP, testVIP4}, ipv6)
	runGatewayPass(t, r)
	runGatewayPass(t, r)

	engine.mu.Lock()
	desired := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]
	engine.mu.Unlock()
	if !slices.Equal(desired.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) {
		t.Errorf("loaded VIPs = %v, want only %s", desired.VIPAddresses, testVIP)
	}
	if _, ok := advertisedPrefixes(t, c, testRuleAdv); !ok {
		t.Error("-v6 not advertised")
	}
	if _, ok := advertisedPrefixes(t, c, testIPv4AdvName); ok {
		t.Error("-v4 advertised with no Healthy IPv4 backend")
	}
	conds := ruleConditions(t, c, rule.Name)
	if cond := meta.FindStatusCondition(conds, ipv4ServedConditionType(testNodeGWA)); cond == nil ||
		cond.Reason != reasonIPv4NoHealthyBackends {
		t.Errorf("IPv4Served = %+v, want reason %s", cond, reasonIPv4NoHealthyBackends)
	}
	got := &bgpv1alpha1.NetworkService{Status: bgpv1alpha1.NetworkServiceStatus{Conditions: conds}}
	if !ipv4LoadedOnSomeNode(got) {
		t.Error("galactic-router would not write the IPv4 bindings")
	}
}

// TestNetworkServiceBindingReconciler_IPv4BindingsWhileNoHealthyBackends: a
// gateway node that holds a FailClosed rule's IPv4 VIP out because no backend
// is Healthy yet still gets the IPv4 bindings, whose health results are what
// let the VIP serve.
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
