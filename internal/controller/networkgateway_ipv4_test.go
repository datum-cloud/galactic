// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// TestNetworkGatewayReconciler_WithholdsIPv4VIPs covers a node with IPv4VIPs
// off: an IPv4 VIP is never loaded or advertised, a "-v4" advertisement this
// node made is withdrawn, the rule's IPv6 VIP keeps serving, and the
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
// and leaves another live gateway node's alone.
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
		WithObjects(newTestGateway(testNodeGWA), newTestGateway(testNodeGWB), newTestRouter(), backendRouter,
			backendAdv, backendVRF,
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

	dr, _, _, err := buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4, testVIP), attachments, idx, nil,
		false, nil)
	if err != nil {
		t.Fatalf("dual-stack rule: %v", err)
	}
	if !slices.Equal(dr.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) {
		t.Errorf("dual-stack rule VIPs = %v, want only %s", dr.VIPAddresses, testVIP)
	}

	_, _, _, err = buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4, "198.51.100.7"), attachments, idx,
		nil, false, nil)
	if !errors.Is(err, errNoServedVIP) {
		t.Errorf("IPv4-only rule: err = %v, want errNoServedVIP", err)
	}

	_, _, _, err = buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4, "not-an-ip"), attachments, idx,
		nil, false, nil)
	if err == nil || errors.Is(err, errNoServedVIP) {
		t.Errorf("rule with an unparseable VIP: err = %v, want a parse error", err)
	}

	mapped := newTestRule(testRuleName, "vpc-1", testVIP, "::ffff:203.0.113.5")
	if !hasIPv4VIP(mapped) {
		t.Error("hasIPv4VIP missed an IPv4-mapped IPv6 VIP")
	}
	dr, _, _, err = buildDesiredRule(mapped, attachments, idx, nil, false, nil)
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

			o, draining, err := r.drainingOutcome(context.Background(), rule, attachments, idx, nil, nil)
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

// TestBuildDesiredRule_ServesIPv4WhenEnabled covers the IPv4VIPs switch: IPv4
// VIPs, plain or IPv4-mapped, load beside the IPv6 one in their plain form,
// both families over the attachment's IPv6 address, never its IPv4 one, with
// the slot the backend node keys both bindings on, and an IPv4-only rule
// builds instead of failing.
func TestBuildDesiredRule_ServesIPv4WhenEnabled(t *testing.T) {
	idx := newTestSIDIndex()
	attachments := []*cloudv1alpha1.VPCAttachment{newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4)}

	dr, unresolved, _, err := buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP, "::ffff:"+testVIP4),
		attachments, idx, nil, true, nil)
	if err != nil {
		t.Fatalf("dual-stack rule: %v", err)
	}
	if len(unresolved) != 0 {
		t.Errorf("unresolved = %v, want none", unresolved)
	}
	want := []netip.Addr{netip.MustParseAddr(testVIP), netip.MustParseAddr(testVIP4)}
	if !slices.Equal(dr.VIPAddresses, want) {
		t.Errorf("VIPs = %v, want %v", dr.VIPAddresses, want)
	}
	for _, tc := range []struct {
		family   addrFamily
		backends []gateway.DesiredBackend
		addr     string
	}{
		{familyIPv6, dr.Backends, testBackendAddr},
		{familyIPv4, dr.IPv4Backends, testBackendAddr},
	} {
		addr := netip.MustParseAddr(tc.addr)
		if len(tc.backends) != 1 || tc.backends[0].Address != addr {
			t.Errorf("%s backends = %+v, want only %s", tc.family, tc.backends, addr)
			continue
		}
		fields, err := uformat.Decode(tc.backends[0].USID)
		if err != nil {
			t.Fatalf("decode %s backend uSID: %v", tc.family, err)
		}
		if want := srv6.BackendSlot(addr, testBackendPort); fields.Slot != want {
			t.Errorf("%s backend slot = %#04x, want %#04x, the slot its node keys the binding on",
				tc.family, fields.Slot, want)
		}
	}

	if len(dr.Backends) == 1 && len(dr.IPv4Backends) == 1 && dr.Backends[0] != dr.IPv4Backends[0] {
		t.Errorf("IPv4 VIP backend %+v differs from the IPv6 VIP's %+v; want the same backend and uSID",
			dr.IPv4Backends[0], dr.Backends[0])
	}

	dr, _, _, err = buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4), attachments, idx, nil, true, nil)
	if err != nil {
		t.Fatalf("IPv4-only rule with IPv4 VIPs served: %v", err)
	}
	if len(dr.Backends) != 0 || len(dr.IPv4Backends) != 1 {
		t.Errorf("IPv4-only rule backends = %+v / %+v, want only the IPv4 VIP's", dr.Backends, dr.IPv4Backends)
	}
}

// TestBuildDesiredRule_IPv4FamilyWithoutBackends covers an IPv4 VIP with no
// IPv6 backend of its own: where another rule owns the backend's claim for an
// IPv4 VIP, the IPv4 VIP is left out with NoBackend and the backend named in
// unresolved while the IPv6 VIP still serves over it; and an attachment with
// only an IPv4 address is no backend at all, so an IPv4-only rule fails.
func TestBuildDesiredRule_IPv4FamilyWithoutBackends(t *testing.T) {
	idx := newTestSIDIndex()
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	attachments := []*cloudv1alpha1.VPCAttachment{newBackendAttachment("vpc-1", testBackendAddr)}
	backend := ruleBackend{addr: netip.MustParseAddr(testBackendAddr), port: testBackendPort}
	owners := backendOwners{
		backendClaimFor(rule, backend, familyIPv4): {Namespace: testNamespace, Name: "older-rule"},
	}

	dr, unresolved, ipv4, err := buildDesiredRule(rule, attachments, idx, owners, true, nil)
	if err != nil {
		t.Fatalf("dual-stack rule: %v", err)
	}
	if ipv4 != ipv4NoBackend {
		t.Errorf("ipv4 = %d, want %d", ipv4, ipv4NoBackend)
	}
	if !slices.Equal(dr.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) || len(dr.IPv4Backends) != 0 ||
		len(dr.Backends) != 1 {
		t.Errorf("loaded VIPs %v over %v, IPv4 backends %v; want only %s over the backend",
			dr.VIPAddresses, dr.Backends, dr.IPv4Backends, testVIP)
	}
	if !slices.ContainsFunc(unresolved, func(u string) bool { return strings.Contains(u, testBackendAddr) }) {
		t.Errorf("unresolved = %v, want the claimed %s among them", unresolved, testBackendAddr)
	}

	ipv4Only := []*cloudv1alpha1.VPCAttachment{newBackendAttachment("vpc-1", testBackendAddr4)}
	_, unresolved, ipv4, err = buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4), ipv4Only, idx, nil,
		true, nil)
	if err == nil || ipv4 != ipv4NoBackend {
		t.Errorf("IPv4-only rule over an IPv4-only attachment: err = %v, ipv4 = %d; want an error and %d",
			err, ipv4, ipv4NoBackend)
	}
	if want := "tenant-vpc-1/backend-vpc-1: no IPv6 address"; !slices.Contains(unresolved, want) && err != nil &&
		!strings.Contains(err.Error(), "no IPv6 address") {
		t.Errorf("unresolved %v, err %v; want %q", unresolved, err, want)
	}
}

// TestBuildDesiredRule_SecondIPv4VIP covers a rule with two IPv4 VIPs: none
// of them loads, with or without IPv4VIPs, and the IPv6 VIP serves either
// way. With IPv4VIPs set the result says why, and a rule with no other VIP
// fails.
func TestBuildDesiredRule_SecondIPv4VIP(t *testing.T) {
	idx := newTestSIDIndex()
	attachments := []*cloudv1alpha1.VPCAttachment{newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4)}
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4, "198.51.100.7")

	for _, tc := range []struct {
		serveIPv4 bool
		want      ipv4Family
	}{{true, ipv4MultipleVIPs}, {false, ipv4Off}} {
		dr, _, ipv4, err := buildDesiredRule(rule, attachments, idx, nil, tc.serveIPv4, nil)
		if err != nil {
			t.Fatalf("IPv4VIPs %v: %v", tc.serveIPv4, err)
		}
		if !slices.Equal(dr.VIPAddresses, []netip.Addr{netip.MustParseAddr(testVIP)}) || len(dr.IPv4Backends) != 0 {
			t.Errorf("IPv4VIPs %v: loaded VIPs %v, IPv4 backends %v; want only %s",
				tc.serveIPv4, dr.VIPAddresses, dr.IPv4Backends, testVIP)
		}
		if ipv4 != tc.want {
			t.Errorf("IPv4VIPs %v: ipv4 = %d, want %d", tc.serveIPv4, ipv4, tc.want)
		}
	}

	_, _, ipv4, err := buildDesiredRule(newTestRule(testRuleName, "vpc-1", testVIP4, "198.51.100.7"), attachments,
		idx, nil, true, nil)
	if err == nil || ipv4 != ipv4MultipleVIPs {
		t.Errorf("IPv4-only rule with two IPv4 VIPs: err = %v, ipv4 = %d; want an error and %d",
			err, ipv4, ipv4MultipleVIPs)
	}
}

// TestIPv4ServedCondition covers each IPv4Served reason, that only an
// advertised IPv4 VIP is True, and which reasons count as loaded for the
// backend nodes.
func TestIPv4ServedCondition(t *testing.T) {
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	for _, tc := range []struct {
		name       string
		ipv4       ipv4Family
		programmed bool
		advertised bool
		want       string
		wantStatus metav1.ConditionStatus
		wantLoaded bool
	}{
		{"SwitchOff", ipv4Off, true, true, reasonIPv4Unsupported, metav1.ConditionFalse, false},
		{"Advertised", ipv4Loaded, true, true, reasonIPv4Advertised, metav1.ConditionTrue, true},
		{"LoadedRouteNotPublished", ipv4Loaded, true, false, reasonIPv4NotAdvertised, metav1.ConditionFalse, true},
		{"BindingsNotBound", ipv4Unbound, true, true, reasonIPv4BindingsNotBound, metav1.ConditionFalse, true},
		{"LoadedButRuleNotLoaded", ipv4Loaded, false, false, reasonIPv4NotLoaded, metav1.ConditionFalse, false},
		{"UnboundButRuleNotLoaded", ipv4Unbound, false, false, reasonIPv4NotLoaded, metav1.ConditionFalse, false},
		{"NoBackend", ipv4NoBackend, true, true, reasonIPv4NoBackend, metav1.ConditionFalse, false},
		{"MultipleVIPs", ipv4MultipleVIPs, true, true, reasonIPv4MultipleVIPs, metav1.ConditionFalse, false},
		{"RuleFailed", ipv4NotLoaded, false, false, reasonIPv4NotLoaded, metav1.ConditionFalse, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ipv4ServedCondition(testNodeGWA, rule, tc.ipv4, tc.programmed, tc.advertised)
			if c == nil || c.Status != tc.wantStatus || c.Reason != tc.want {
				t.Fatalf("IPv4Served = %+v, want %s/%s", c, tc.wantStatus, tc.want)
			}
			withCond := rule.DeepCopy()
			withCond.Status.Conditions = []metav1.Condition{*c}
			if got := ipv4LoadedOnSomeNode(withCond); got != tc.wantLoaded {
				t.Errorf("ipv4LoadedOnSomeNode = %v, want %v", got, tc.wantLoaded)
			}
		})
	}
	if c := ipv4ServedCondition(testNodeGWA, newTestRule(testRuleName, "vpc-1", testVIP), ipv4Loaded, true,
		true); c != nil {
		t.Errorf("rule with no IPv4 VIP: IPv4Served = %+v, want none", c)
	}
	advertised := rule.DeepCopy()
	advertised.Status.Conditions = []metav1.Condition{{
		Type: ipv4ServedConditionType(testNodeGWB), Status: metav1.ConditionTrue, Reason: reasonIPv4Advertised,
	}}
	if !ipv4LoadedOnSomeNode(advertised) {
		t.Error("ipv4LoadedOnSomeNode ignores a node reporting its IPv4 VIP advertised")
	}
}

// TestNetworkGatewayReconciler_IPv4WithoutBackendKeepsIPv6 covers a node
// with IPv4VIPs set and a rule whose one backend an older rule's IPv4 VIP
// already owns: the IPv6 VIP is programmed over it, and IPv4Served reports
// NoBackend, not loaded.
func TestNetworkGatewayReconciler_IPv4WithoutBackendKeepsIPv6(t *testing.T) {
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	rule.CreationTimestamp = metav1.NewTime(time.Unix(2000, 0))
	acceptRule(rule)
	older := newTestRule("older-rule", "vpc-1", "203.0.113.9")
	older.CreationTimestamp = metav1.NewTime(time.Unix(1000, 0))
	acceptRule(older)
	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
			newBackendAttachment("vpc-1", testBackendAddr), rule, older).
		Build()
	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)
	r.IPv4VIPs = true
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := &bgpv1alpha1.NetworkService{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleName), got); err != nil {
		t.Fatalf("get NetworkService: %v", err)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, programmedConditionType(testNodeGWA)) {
		t.Errorf("Programmed = %+v, want True", got.Status.Conditions)
	}
	ipv4 := meta.FindStatusCondition(got.Status.Conditions, ipv4ServedConditionType(testNodeGWA))
	if ipv4 == nil || ipv4.Reason != reasonIPv4NoBackend {
		t.Errorf("IPv4Served = %+v, want reason %s", ipv4, reasonIPv4NoBackend)
	}
}

// newTestSIDIndex returns the uSID index newBackendFixtures' objects for
// vpc-1 build.
func newTestSIDIndex() *backendSIDIndex {
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	return &backendSIDIndex{
		routers:      map[string]*bgpv1alpha1.BGPRouter{backendRouter.Name: backendRouter},
		advs:         []*bgpv1alpha1.BGPAdvertisement{backendAdv},
		vrfInstances: map[string]*bgpv1alpha1.BGPVRFInstance{backendVRF.Name: backendVRF},
	}
}

// TestNetworkGatewayReconciler_LoadsIPv4WithoutBoundBindings covers a node
// with IPv4VIPs set and no ServiceVIPBinding for the IPv4 VIP yet: the
// IPv4 VIP reaches the engine over that backend, so the backend nodes write
// their bindings, but no -v4 advertisement is made and an old one is
// withdrawn, and IPv4Served says the bindings are not Bound.
func TestNetworkGatewayReconciler_LoadsIPv4WithoutBoundBindings(t *testing.T) {
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	acceptRule(rule)
	staleV4 := newNodeAdvertisement(testRuleName, testNodeGWA, "v4")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
			newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4), rule, staleV4).
		Build()
	ctx := context.Background()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	r.IPv4VIPs = true
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	desired := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]
	if !slices.Contains(desired.VIPAddresses, netip.MustParseAddr(testVIP4)) {
		t.Errorf("loaded VIPs = %v, want %s among them", desired.VIPAddresses, testVIP4)
	}
	if len(desired.IPv4Backends) != 1 || desired.IPv4Backends[0].Address != netip.MustParseAddr(testBackendAddr) {
		t.Errorf("IPv4 backends = %+v, want only the IPv6 backend %s", desired.IPv4Backends, testBackendAddr)
	}
	err := fakeClient.Get(ctx, testRuleKey(staleV4.Name), &bgpv1alpha1.BGPAdvertisement{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("-v4 advertisement: err = %v, want NotFound", err)
	}
	if err := fakeClient.Get(ctx, testRuleKey(testRuleAdv), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("-v6 advertisement: %v", err)
	}

	got := &bgpv1alpha1.NetworkService{}
	if err := fakeClient.Get(ctx, testRuleKey(testRuleName), got); err != nil {
		t.Fatalf("get NetworkService: %v", err)
	}
	ipv4 := meta.FindStatusCondition(got.Status.Conditions, ipv4ServedConditionType(testNodeGWA))
	if ipv4 == nil || ipv4.Status != metav1.ConditionFalse || ipv4.Reason != reasonIPv4BindingsNotBound {
		t.Errorf("IPv4Served = %+v, want False/%s", ipv4, reasonIPv4BindingsNotBound)
	}
}
