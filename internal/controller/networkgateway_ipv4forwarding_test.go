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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// forwardingRecorder is an EnsureIPv4Forwarding that records each call and
// whether the engine had been driven yet when it came.
type forwardingRecorder struct {
	engine         *fakeGatewayEngine
	calls          int
	afterReconcile bool
	err            error
}

func (f *forwardingRecorder) ensure() error {
	f.calls++
	f.engine.mu.Lock()
	if f.engine.reconciled > 0 {
		f.afterReconcile = true
	}
	f.engine.mu.Unlock()
	return f.err
}

// newForwardingGateway returns a reconciler for testNodeGWA over a rule with
// vips, backed by one attachment with an IPv6 address, whose IPv4 forwarding
// calls go to the returned recorder.
func newForwardingGateway(
	t *testing.T, ipv4VIPs bool, vips ...string,
) (client.Client, *fakeGatewayEngine, *forwardingRecorder, *NetworkGatewayReconciler) {
	t.Helper()
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", vips...)
	acceptRule(rule)
	c := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{},
			&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
			newBackendAttachment("vpc-1", testBackendAddr), rule).
		Build()
	engine := newFakeGatewayEngine()
	rec := &forwardingRecorder{engine: engine}
	r := newGatewayReconciler(c, scheme, engine, testNodeGWA)
	r.IPv4VIPs = ipv4VIPs
	r.EnsureIPv4Forwarding = rec.ensure
	return c, engine, rec, r
}

// TestNetworkGatewayReconciler_IPv4ForwardingFollowsNeed covers when a pass
// turns on IPv4 forwarding: only with the switch on and an IPv4 VIP about to
// load, and always before the engine loads it.
func TestNetworkGatewayReconciler_IPv4ForwardingFollowsNeed(t *testing.T) {
	tests := []struct {
		name      string
		ipv4VIPs  bool
		vips      []string
		wantCalls bool
	}{
		{name: "IPv4 VIP to load", ipv4VIPs: true, vips: []string{testVIP, testVIP4}, wantCalls: true},
		{name: "IPv6 VIPs only", ipv4VIPs: true, vips: []string{testVIP}},
		{name: "switch off", ipv4VIPs: false, vips: []string{testVIP, testVIP4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, engine, rec, r := newForwardingGateway(t, tt.ipv4VIPs, tt.vips...)
			runGatewayPass(t, r)
			if got := rec.calls > 0; got != tt.wantCalls {
				t.Fatalf("EnsureIPv4Forwarding called %d times, want called = %v", rec.calls, tt.wantCalls)
			}
			if rec.afterReconcile {
				t.Error("EnsureIPv4Forwarding called after the engine was driven, want before")
			}
			if engine.reconciled != 1 {
				t.Errorf("engine reconciled %d times, want 1", engine.reconciled)
			}
		})
	}
}

// TestNetworkGatewayReconciler_IPv4ForwardingFailure covers a node that
// cannot turn on IPv4 forwarding: IPv4 fails closed for the pass, with no
// IPv4 VIP loaded or advertised, while IPv6 keeps being loaded, advertised
// and updated, and the IPv4 VIP returns once forwarding succeeds.
func TestNetworkGatewayReconciler_IPv4ForwardingFailure(t *testing.T) {
	c, engine, rec, r := newForwardingGateway(t, true, testVIP, testVIP4)
	rec.err = errors.New("injected sysctl failure")
	key := testNamespace + "/" + testRuleName
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)})
	if !errors.Is(err, rec.err) {
		t.Fatalf("Reconcile error = %v, want the injected sysctl failure", err)
	}
	desired, ok := engine.lastDesired.Rules[key]
	if !ok || !slices.Equal(desired.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) ||
		len(desired.IPv4Backends) != 0 {
		t.Fatalf("engine state = %+v (loaded %v), want the rule with its IPv6 VIP only", desired, ok)
	}
	if _, ok := advertisedPrefixes(t, c, testIPv4AdvName); ok {
		t.Error("-v4 advertised though IPv4 forwarding could not be turned on")
	}
	if v6, ok := advertisedPrefixes(t, c, testRuleAdv); !ok || !slices.Equal(v6, []bgpv1alpha1.Prefix{testVIPPrefix}) {
		t.Errorf("-v6 = %v (exists %v), want %s", v6, ok, testVIPPrefix)
	}
	gw := &bgpv1alpha1.NetworkGateway{}
	if err := c.Get(ctx, testRuleKey(testNodeGWA), gw); err != nil {
		t.Fatal(err)
	}
	ready := meta.FindStatusCondition(gw.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != reasonIPv4ForwardingFailed {
		t.Errorf("Ready = %+v, want False/%s", ready, reasonIPv4ForwardingFailed)
	}
	ipv4 := meta.FindStatusCondition(ruleConditions(t, c, testRuleName), ipv4ServedConditionType(testNodeGWA))
	if ipv4 == nil || ipv4.Status != metav1.ConditionFalse || ipv4.Reason != reasonIPv4ForwardingFailed {
		t.Errorf("IPv4Served = %+v, want False/%s", ipv4, reasonIPv4ForwardingFailed)
	}

	// An IPv6 change still applies while the write keeps failing.
	rule := &bgpv1alpha1.NetworkService{}
	if err := c.Get(ctx, testRuleKey(testRuleName), rule); err != nil {
		t.Fatal(err)
	}
	rule.Spec.Port = 8443
	if err := c.Update(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); !errors.Is(err, rec.err) {
		t.Fatalf("Reconcile error = %v, want the injected sysctl failure", err)
	}
	if got := engine.lastDesired.Rules[key].Port; got != 8443 {
		t.Errorf("engine port = %d while forwarding fails, want the updated 8443", got)
	}

	rec.err = nil
	runGatewayPass(t, r)
	desired = engine.lastDesired.Rules[key]
	if !slices.Contains(desired.VIPAddresses, netip.MustParseAddr(testVIP4)) {
		t.Errorf("engine VIPs = %v once forwarding succeeded, want the IPv4 VIP back", desired.VIPAddresses)
	}
}

// TestNetworkGatewayReconciler_IPv4OnlyRuleWithoutForwarding covers a rule
// whose every VIP is IPv4 on a pass where forwarding cannot be turned on: it
// is not loaded and reports serving no VIP, while the pass still applies.
func TestNetworkGatewayReconciler_IPv4OnlyRuleWithoutForwarding(t *testing.T) {
	c, engine, rec, r := newForwardingGateway(t, true, testVIP4)
	rec.err = errors.New("injected sysctl failure")
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err == nil {
		t.Fatal("Reconcile succeeded, want the injected sysctl failure")
	}
	if engine.reconciled != 1 {
		t.Errorf("engine reconciled %d times, want 1", engine.reconciled)
	}
	if _, ok := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]; ok {
		t.Error("IPv4-only rule loaded though IPv4 forwarding could not be turned on")
	}
	programmed := meta.FindStatusCondition(ruleConditions(t, c, testRuleName), programmedConditionType(testNodeGWA))
	if programmed == nil || programmed.Status != metav1.ConditionFalse || programmed.Reason != reasonNoServedVIP {
		t.Errorf("Programmed = %+v, want False/%s", programmed, reasonNoServedVIP)
	}
}
