// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// testBindFailed is the Bound reason ServiceVIPBindingReconciler sets when
// programming a binding fails.
const testBindFailed = "BindFailed"

// testIPv4AdvName is the -v4 advertisement testNodeGWA makes for testRuleName.
var testIPv4AdvName = ruleAdvertisementName(testRuleName, testNodeGWA, "v4")

// newIPv4Binding returns the binding testComputeNodeName writes for rule's
// IPv4 VIP testVIP4 and the IPv4 backend at addr, with its Bound condition set to
// status and reason for its current generation.
func newIPv4Binding(
	rule *bgpv1alpha1.NetworkService, addr string, status metav1.ConditionStatus, reason string,
) *bgpv1alpha1.ServiceVIPBinding {
	b := generatedBinding(rule, testComputeNodeName, netip.MustParseAddr(testVIP4), ruleBackend{
		node:       testComputeNodeName,
		addr:       netip.MustParseAddr(addr),
		port:       testBackendPort,
		egressKind: bgpv1alpha1.ServiceVIPBindingEgressKindVeth,
	})
	b.Generation = 1
	b.Status.Conditions = []metav1.Condition{{
		Type: bgpv1alpha1.ConditionTypeBound, Status: status, Reason: reason, ObservedGeneration: 1,
		LastTransitionTime: metav1.Now(),
	}}
	return b
}

// reconcileGateway runs one testNodeGWA pass over objs and returns the client
// and the engine state it converged to.
func reconcileGateway(
	t *testing.T, ipv4VIPs bool, objs ...client.Object,
) (client.Client, *fakeGatewayEngine, *NetworkGatewayReconciler) {
	t.Helper()
	scheme := newRuleTestScheme(t)
	c := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{},
			&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(objs...).
		Build()
	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(c, scheme, engine, testNodeGWA)
	r.IPv4VIPs = ipv4VIPs
	runGatewayPass(t, r)
	return c, engine, r
}

// runGatewayPass reconciles testNodeGWA's NetworkGateway once.
func runGatewayPass(t *testing.T, r *NetworkGatewayReconciler) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

// ruleConditions returns name's conditions.
func ruleConditions(t *testing.T, c client.Client, name string) []metav1.Condition {
	t.Helper()
	got := &bgpv1alpha1.NetworkService{}
	if err := c.Get(context.Background(), testRuleKey(name), got); err != nil {
		t.Fatalf("get NetworkService %s: %v", name, err)
	}
	return got.Status.Conditions
}

// advertisedPrefixes returns the prefixes of advertisement name, or nil and
// false when it does not exist.
func advertisedPrefixes(t *testing.T, c client.Client, name string) ([]bgpv1alpha1.Prefix, bool) {
	t.Helper()
	adv := &bgpv1alpha1.BGPAdvertisement{}
	err := c.Get(context.Background(), testRuleKey(name), adv)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("get BGPAdvertisement %s: %v", name, err)
	}
	return adv.Spec.Prefixes, true
}

// TestIPv4Gate covers each state of the IPv4 advertisement gate on one node:
// it opens only with IPv4VIPs on, the IPv4 VIP loaded, an eligible IPv4
// backend and that backend's binding Bound for its current spec, and every
// other state leaves -v4 unadvertised with its own IPv4Served reason, while
// the rule's IPv6 VIP is advertised as before.
func TestIPv4Gate(t *testing.T) {
	dualStack := func() *bgpv1alpha1.NetworkService {
		rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
		acceptRule(rule)
		return rule
	}
	bound := func(rule *bgpv1alpha1.NetworkService) *bgpv1alpha1.ServiceVIPBinding {
		return newIPv4Binding(rule, testBackendAddr4, metav1.ConditionTrue, "Bound")
	}
	dualAttachment := newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4)

	tests := []struct {
		name           string
		ipv4VIPs       bool
		noRouter       bool
		rule           *bgpv1alpha1.NetworkService
		attachment     client.Object
		binding        func(*bgpv1alpha1.NetworkService) *bgpv1alpha1.ServiceVIPBinding
		wantStatus     metav1.ConditionStatus
		wantReason     string
		wantV4Loaded   bool
		wantV4Advert   bool
		wantV6Advert   bool
		wantProgrammed metav1.ConditionStatus
	}{
		{
			name: "open", ipv4VIPs: true, rule: dualStack(), attachment: dualAttachment, binding: bound,
			wantStatus: metav1.ConditionTrue, wantReason: reasonIPv4Advertised,
			wantV4Loaded: true, wantV4Advert: true, wantV6Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "IPv4-only rule opens", ipv4VIPs: true,
			rule: func() *bgpv1alpha1.NetworkService {
				rule := newTestRule(testRuleName, "vpc-1", testVIP4)
				acceptRule(rule)
				return rule
			}(),
			attachment: dualAttachment, binding: bound,
			wantStatus: metav1.ConditionTrue, wantReason: reasonIPv4Advertised,
			wantV4Loaded: true, wantV4Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "switch off", rule: dualStack(), attachment: dualAttachment, binding: bound,
			wantStatus: metav1.ConditionFalse, wantReason: reasonIPv4Unsupported,
			wantV6Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "binding not created", ipv4VIPs: true, rule: dualStack(), attachment: dualAttachment,
			wantStatus: metav1.ConditionFalse, wantReason: reasonIPv4BindingsNotBound,
			wantV4Loaded: true, wantV6Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "binding failed", ipv4VIPs: true, rule: dualStack(), attachment: dualAttachment,
			binding: func(rule *bgpv1alpha1.NetworkService) *bgpv1alpha1.ServiceVIPBinding {
				return newIPv4Binding(rule, testBackendAddr4, metav1.ConditionFalse, testBindFailed)
			},
			wantStatus: metav1.ConditionFalse, wantReason: reasonIPv4BindingsNotBound,
			wantV4Loaded: true, wantV6Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "binding Bound for an older generation", ipv4VIPs: true, rule: dualStack(),
			attachment: dualAttachment,
			binding: func(rule *bgpv1alpha1.NetworkService) *bgpv1alpha1.ServiceVIPBinding {
				b := bound(rule)
				b.Generation = 2
				return b
			},
			wantStatus: metav1.ConditionFalse, wantReason: reasonIPv4BindingsNotBound,
			wantV4Loaded: true, wantV6Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "binding for an earlier spec", ipv4VIPs: true, rule: dualStack(), attachment: dualAttachment,
			binding: func(rule *bgpv1alpha1.NetworkService) *bgpv1alpha1.ServiceVIPBinding {
				b := bound(rule)
				b.Spec.Port = 80
				return b
			},
			wantStatus: metav1.ConditionFalse, wantReason: reasonIPv4BindingsNotBound,
			wantV4Loaded: true, wantV6Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "no BGPRouter", ipv4VIPs: true, noRouter: true, rule: dualStack(), attachment: dualAttachment,
			binding:    bound,
			wantStatus: metav1.ConditionFalse, wantReason: reasonIPv4NotAdvertised,
			wantV4Loaded: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "no IPv4 backend", ipv4VIPs: true, rule: dualStack(), attachment: newBackendAttachment("vpc-1"),
			wantStatus: metav1.ConditionFalse, wantReason: reasonIPv4NoBackend,
			wantV6Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
		{
			name: "two IPv4 VIPs stored before admission refused them", ipv4VIPs: true,
			rule: func() *bgpv1alpha1.NetworkService {
				rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4, "198.51.100.7")
				acceptRule(rule)
				return rule
			}(),
			attachment: dualAttachment, binding: bound,
			wantStatus: metav1.ConditionFalse, wantReason: reasonIPv4MultipleVIPs,
			wantV6Advert: true, wantProgrammed: metav1.ConditionTrue,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
			objs := []client.Object{newTestGateway(testNodeGWA), backendRouter, backendAdv, backendVRF,
				tt.attachment, tt.rule}
			if !tt.noRouter {
				objs = append(objs, newTestRouter())
			}
			if tt.binding != nil {
				objs = append(objs, tt.binding(tt.rule))
			}
			c, engine, _ := reconcileGateway(t, tt.ipv4VIPs, objs...)

			desired := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]
			v4Loaded := slices.Contains(desired.VIPAddresses, netip.MustParseAddr(testVIP4))
			if v4Loaded != tt.wantV4Loaded {
				t.Errorf("IPv4 VIP loaded = %v, want %v (VIPs %v)", v4Loaded, tt.wantV4Loaded, desired.VIPAddresses)
			}
			if v4Loaded && (len(desired.IPv4Backends) != 1 ||
				desired.IPv4Backends[0].Address != netip.MustParseAddr(testBackendAddr4)) {
				t.Errorf("IPv4 backends = %+v, want only %s", desired.IPv4Backends, testBackendAddr4)
			}

			v4, ok := advertisedPrefixes(t, c, testIPv4AdvName)
			if ok != tt.wantV4Advert {
				t.Errorf("-v4 advertised = %v, want %v", ok, tt.wantV4Advert)
			}
			if ok && !slices.Equal(v4, []bgpv1alpha1.Prefix{testVIP4 + "/32"}) {
				t.Errorf("-v4 prefixes = %v, want %s/32", v4, testVIP4)
			}
			v6, ok := advertisedPrefixes(t, c, testRuleAdv)
			if ok != tt.wantV6Advert {
				t.Errorf("-v6 advertised = %v, want %v", ok, tt.wantV6Advert)
			}
			if ok && !slices.Equal(v6, []bgpv1alpha1.Prefix{testVIPPrefix}) {
				t.Errorf("-v6 prefixes = %v, want %s", v6, testVIPPrefix)
			}

			conds := ruleConditions(t, c, testRuleName)
			ipv4 := meta.FindStatusCondition(conds, ipv4ServedConditionType(testNodeGWA))
			if ipv4 == nil || ipv4.Status != tt.wantStatus || ipv4.Reason != tt.wantReason {
				t.Errorf("IPv4Served = %+v, want %s/%s", ipv4, tt.wantStatus, tt.wantReason)
			}
			programmed := meta.FindStatusCondition(conds, programmedConditionType(testNodeGWA))
			if programmed == nil || programmed.Status != tt.wantProgrammed {
				t.Errorf("Programmed = %+v, want %s", programmed, tt.wantProgrammed)
			}
		})
	}
}

// TestIPv4Gate_WithdrawsWhenBindingStopsBeingBound covers the gate closing:
// once the IPv4 backend's binding is no longer Bound, the next pass withdraws
// -v4 and reports BindingsNotBound, and the IPv6 advertisement is untouched.
func TestIPv4Gate_WithdrawsWhenBindingStopsBeingBound(t *testing.T) {
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	acceptRule(rule)
	binding := newIPv4Binding(rule, testBackendAddr4, metav1.ConditionTrue, "Bound")
	c, _, r := reconcileGateway(t, true, newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv,
		backendVRF, newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4), rule, binding)
	if _, ok := advertisedPrefixes(t, c, testIPv4AdvName); !ok {
		t.Fatal("-v4 not advertised with the binding Bound")
	}

	ctx := context.Background()
	current := &bgpv1alpha1.ServiceVIPBinding{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(binding), current); err != nil {
		t.Fatal(err)
	}
	meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{
		Type: bgpv1alpha1.ConditionTypeBound, Status: metav1.ConditionFalse, Reason: testBindFailed,
		ObservedGeneration: current.Generation,
	})
	if err := c.Status().Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	runGatewayPass(t, r)

	if _, ok := advertisedPrefixes(t, c, testIPv4AdvName); ok {
		t.Error("-v4 still advertised after its binding stopped being Bound")
	}
	if v6, ok := advertisedPrefixes(t, c, testRuleAdv); !ok || !slices.Equal(v6, []bgpv1alpha1.Prefix{testVIPPrefix}) {
		t.Errorf("-v6 = %v (exists %v), want %s", v6, ok, testVIPPrefix)
	}
	ipv4 := meta.FindStatusCondition(ruleConditions(t, c, testRuleName), ipv4ServedConditionType(testNodeGWA))
	if ipv4 == nil || ipv4.Status != metav1.ConditionFalse || ipv4.Reason != reasonIPv4BindingsNotBound {
		t.Errorf("IPv4Served = %+v, want False/%s", ipv4, reasonIPv4BindingsNotBound)
	}
}

// TestIPv4Gate_LeavesUnboundBackendsOut covers a rule with two IPv4 backends,
// one Bound: the IPv4 VIP is balanced over the Bound one alone and advertised,
// and the other is named on the Programmed condition until it is Bound.
func TestIPv4Gate_LeavesUnboundBackendsOut(t *testing.T) {
	const secondAddr4 = "10.60.0.6"
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	acceptRule(rule)
	c, engine, _ := reconcileGateway(t, true, newTestGateway(testNodeGWA), newTestRouter(), backendRouter,
		backendAdv, backendVRF, newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4, secondAddr4), rule,
		newIPv4Binding(rule, testBackendAddr4, metav1.ConditionTrue, "Bound"),
		newIPv4Binding(rule, secondAddr4, metav1.ConditionFalse, "Conflict"))

	desired := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]
	if len(desired.IPv4Backends) != 1 || desired.IPv4Backends[0].Address != netip.MustParseAddr(testBackendAddr4) {
		t.Errorf("IPv4 backends = %+v, want only the Bound %s", desired.IPv4Backends, testBackendAddr4)
	}
	if _, ok := advertisedPrefixes(t, c, testIPv4AdvName); !ok {
		t.Error("-v4 not advertised over a Bound backend")
	}
	conds := ruleConditions(t, c, testRuleName)
	programmed := meta.FindStatusCondition(conds, programmedConditionType(testNodeGWA))
	if programmed == nil || programmed.Reason != reasonBackendsUnresolved ||
		!strings.Contains(programmed.Message, secondAddr4) || !strings.Contains(programmed.Message, "Conflict") {
		t.Errorf("Programmed = %+v, want %s naming %s and its binding's reason", programmed,
			reasonBackendsUnresolved, secondAddr4)
	}
	if ipv4 := meta.FindStatusCondition(conds, ipv4ServedConditionType(testNodeGWA)); ipv4 == nil ||
		ipv4.Reason != reasonIPv4Advertised {
		t.Errorf("IPv4Served = %+v, want %s", ipv4, reasonIPv4Advertised)
	}
}

// TestIPv4Gate_SharedBackendSocket covers two rules selecting the same IPv4
// backend on one backendPort and protocol: the older rule owns it and is
// advertised, and the newer IPv4-only rule has no IPv4 backend, so its gate
// stays closed with NoBackend.
func TestIPv4Gate_SharedBackendSocket(t *testing.T) {
	const newerVIP4 = "203.0.113.9"
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	older := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	older.CreationTimestamp = metav1.NewTime(time.Unix(1000, 0))
	acceptRule(older)
	newer := newTestRule("rule-2", "vpc-1", newerVIP4)
	newer.CreationTimestamp = metav1.NewTime(time.Unix(2000, 0))
	acceptRule(newer)

	c, _, _ := reconcileGateway(t, true, newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv,
		backendVRF, newBackendAttachment("vpc-1", testBackendAddr, testBackendAddr4), older, newer,
		newIPv4Binding(older, testBackendAddr4, metav1.ConditionTrue, "Bound"))

	if _, ok := advertisedPrefixes(t, c, testIPv4AdvName); !ok {
		t.Error("older rule's -v4 not advertised")
	}
	if _, ok := advertisedPrefixes(t, c, ruleAdvertisementName("rule-2", testNodeGWA, "v4")); ok {
		t.Error("newer rule's -v4 advertised for a backend the older rule owns")
	}
	ipv4 := meta.FindStatusCondition(ruleConditions(t, c, "rule-2"), ipv4ServedConditionType(testNodeGWA))
	if ipv4 == nil || ipv4.Status != metav1.ConditionFalse || ipv4.Reason != reasonIPv4NoBackend {
		t.Errorf("newer rule IPv4Served = %+v, want False/%s", ipv4, reasonIPv4NoBackend)
	}
}

// TestNetworkGatewayReconciler_PrunesDepartedNodeConditions covers a gateway
// node that left without its conditions being cleared: a live node's pass
// removes its Programmed and IPv4Served conditions, so the backend nodes no
// longer count its IPv4 VIP as loaded, and leaves backend nodes' conditions
// and live gateway nodes' conditions alone.
func TestNetworkGatewayReconciler_PrunesDepartedNodeConditions(t *testing.T) {
	const departed = "gw-gone"
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	acceptRule(rule)
	for _, c := range []metav1.Condition{
		{Type: ipv4ServedConditionType(departed), Status: metav1.ConditionTrue, Reason: reasonIPv4Advertised},
		{Type: programmedConditionType(departed), Status: metav1.ConditionTrue, Reason: reasonProgrammed},
		{Type: ipv4ServedConditionType(testNodeGWB), Status: metav1.ConditionFalse, Reason: reasonIPv4Unsupported},
		{Type: backendsBoundConditionType(testComputeNodeName), Status: metav1.ConditionTrue, Reason: "Bound"},
	} {
		meta.SetStatusCondition(&rule.Status.Conditions, c)
	}

	c, _, _ := reconcileGateway(t, false, newTestGateway(testNodeGWA), newTestGateway(testNodeGWB), newTestRouter(),
		backendRouter, backendAdv, backendVRF, newBackendAttachment("vpc-1"), rule)

	conds := ruleConditions(t, c, testRuleName)
	for _, gone := range []string{ipv4ServedConditionType(departed), programmedConditionType(departed)} {
		if meta.FindStatusCondition(conds, gone) != nil {
			t.Errorf("departed node's %s condition was kept", gone)
		}
	}
	for _, kept := range []string{ipv4ServedConditionType(testNodeGWB), backendsBoundConditionType(testComputeNodeName)} {
		if meta.FindStatusCondition(conds, kept) == nil {
			t.Errorf("%s condition was removed", kept)
		}
	}
	if ipv4LoadedOnSomeNode(&bgpv1alpha1.NetworkService{Status: bgpv1alpha1.NetworkServiceStatus{Conditions: conds}}) {
		t.Error("ipv4LoadedOnSomeNode still counts the departed node")
	}
}

// TestIPv4BindingReadinessChanged covers the ServiceVIPBinding watch's
// predicate: generated IPv4 bindings pass on create, delete, a spec change or
// a change in whether they are Bound, and IPv6 or hand-written bindings and
// unrelated status writes do not.
func TestIPv4BindingReadinessChanged(t *testing.T) {
	rule := newTestRule(testRuleName, "vpc-1", testVIP, testVIP4)
	v4 := newIPv4Binding(rule, testBackendAddr4, metav1.ConditionTrue, "Bound")
	v6 := v4.DeepCopy()
	v6.Spec.VIPAddress, v6.Spec.BackendAddress = testVIP, testBackendAddr
	handWritten := v4.DeepCopy()
	delete(handWritten.Labels, bindingManagedByLabel)
	failed := v4.DeepCopy()
	failed.Status.Conditions[0].Status, failed.Status.Conditions[0].Reason = metav1.ConditionFalse, testBindFailed
	reworded := v4.DeepCopy()
	reworded.Status.Conditions[0].Message = "still bound"
	respecced := v4.DeepCopy()
	respecced.Generation = 2

	p := ipv4BindingReadinessChanged()
	for _, tc := range []struct {
		name string
		got  bool
		want bool
	}{
		{"CreateIPv4", p.Create(event.CreateEvent{Object: v4}), true},
		{"CreateIPv6", p.Create(event.CreateEvent{Object: v6}), false},
		{"CreateHandWritten", p.Create(event.CreateEvent{Object: handWritten}), false},
		{"DeleteIPv4", p.Delete(event.DeleteEvent{Object: v4}), true},
		{"BoundToFailed", p.Update(event.UpdateEvent{ObjectOld: v4, ObjectNew: failed}), true},
		{"SpecChanged", p.Update(event.UpdateEvent{ObjectOld: v4, ObjectNew: respecced}), true},
		{"MessageOnly", p.Update(event.UpdateEvent{ObjectOld: v4, ObjectNew: reworded}), false},
		{"IPv6Changed", p.Update(event.UpdateEvent{ObjectOld: v6, ObjectNew: v6.DeepCopy()}), false},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: passed = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}
