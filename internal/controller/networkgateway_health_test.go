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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
)

const (
	// testHealthyAddr and testSickAddr are the two backends of
	// newHealthAttachment, both resolving through newBackendFixtures.
	testHealthyAddr = testBackendAddr
	testSickAddr    = "fd00:10::2"

	testGatewayHealthUID = types.UID("health-attachment-uid")
)

// newHealthRule returns an accepted rule on testVIP with a healthCheck that
// probes backendPort.
func newHealthRule() *bgpv1alpha1.NetworkService {
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	rule.Spec.HealthCheck = &bgpv1alpha1.NetworkServiceHealthCheck{
		IntervalSeconds: 5, TimeoutSeconds: 2, UnhealthyThreshold: 3, HealthyThreshold: 3,
	}
	acceptRule(rule)
	return rule
}

// newHealthAttachment returns one attachment holding testHealthyAddr and
// testSickAddr, so the rule has two backends.
func newHealthAttachment() *cloudv1alpha1.VPCAttachment {
	a := newBackendAttachment("vpc-1", testHealthyAddr, testSickAddr)
	a.UID = testGatewayHealthUID
	return a
}

// healthBinding returns the binding testComputeNodeName writes for rule's
// IPv6 VIP and the backend at addr, with health h.
func healthBinding(
	rule *bgpv1alpha1.NetworkService, addr string, h *bgpv1alpha1.ServiceVIPBindingHealth,
) *bgpv1alpha1.ServiceVIPBinding {
	b := generatedBinding(rule, "", testComputeNodeName, netip.MustParseAddr(testVIP), ruleBackend{
		node:       testComputeNodeName,
		addr:       netip.MustParseAddr(addr),
		port:       testBackendPort,
		egressKind: bgpv1alpha1.ServiceVIPBindingEgressKindVeth,
	})
	b.Status.Health = h
	return b
}

// decision returns a published decision of state for testGatewayHealthUID on
// backendPort.
func decision(state bgpv1alpha1.BackendHealthState) *bgpv1alpha1.ServiceVIPBindingHealth {
	return &bgpv1alpha1.ServiceVIPBindingHealth{
		State: state, Reason: "ProbeFailed", AttachmentUID: testGatewayHealthUID, Port: testBackendPort,
	}
}

func backendAddrs(backends []gateway.DesiredBackend) []string {
	out := make([]string, 0, len(backends))
	for _, b := range backends {
		out = append(out, b.Address.String())
	}
	slices.Sort(out)
	return out
}

// TestBuildDesiredRule_Health covers which backends a rule with a healthCheck
// is balanced over: only an Unhealthy decision about the backend's current
// attachment and port takes it out, every backend stays when all are
// Unhealthy, and nothing is filtered while health does not apply.
func TestBuildDesiredRule_Health(t *testing.T) {
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	idx := &backendSIDIndex{
		routers:      map[string]*bgpv1alpha1.BGPRouter{backendRouter.Name: backendRouter},
		advs:         []*bgpv1alpha1.BGPAdvertisement{backendAdv},
		vrfInstances: map[string]*bgpv1alpha1.BGPVRFInstance{backendVRF.Name: backendVRF},
	}
	applied := healthGate{apply: true}
	sickAddrPort := "[" + testSickAddr + "]:8443"

	otherUID := decision(bgpv1alpha1.BackendHealthUnhealthy)
	otherUID.AttachmentUID = "an-earlier-attachment"
	otherPort := decision(bgpv1alpha1.BackendHealthUnhealthy)
	otherPort.Port = 9000

	tests := []struct {
		name          string
		noHealthCheck bool
		gate          healthGate
		healthy, sick *bgpv1alpha1.ServiceVIPBindingHealth
		staleSick     bool
		wantBackends  []string
		want          ruleHealth
	}{
		{
			name:         "an Unhealthy backend is left out",
			gate:         applied,
			sick:         decision(bgpv1alpha1.BackendHealthUnhealthy),
			wantBackends: []string{testHealthyAddr},
			want:         ruleHealth{unhealthy: []string{sickAddrPort}},
		},
		{
			name:         "every backend Unhealthy keeps them all",
			gate:         applied,
			healthy:      decision(bgpv1alpha1.BackendHealthUnhealthy),
			sick:         decision(bgpv1alpha1.BackendHealthUnhealthy),
			wantBackends: []string{testHealthyAddr, testSickAddr},
			want: ruleHealth{
				unhealthy: []string{"[" + testHealthyAddr + "]:8443", sickAddrPort}, noneHealthy: true,
			},
		},
		{
			name:         "Unknown stays in",
			gate:         applied,
			sick:         decision(bgpv1alpha1.BackendHealthUnknown),
			wantBackends: []string{testHealthyAddr, testSickAddr},
		},
		{
			name:         "a decision about another attachment is ignored",
			gate:         applied,
			sick:         otherUID,
			wantBackends: []string{testHealthyAddr, testSickAddr},
		},
		{
			name:         "a decision about another port is ignored",
			gate:         applied,
			sick:         otherPort,
			wantBackends: []string{testHealthyAddr, testSickAddr},
		},
		{
			name:         "a binding not updated to the rule is ignored",
			gate:         applied,
			sick:         decision(bgpv1alpha1.BackendHealthUnhealthy),
			staleSick:    true,
			wantBackends: []string{testHealthyAddr, testSickAddr},
		},
		{
			name:         "nothing is filtered while health does not apply",
			gate:         healthGate{why: "backend health is not applied by gateway nodes gw-b"},
			sick:         decision(bgpv1alpha1.BackendHealthUnhealthy),
			wantBackends: []string{testHealthyAddr, testSickAddr},
			want:         ruleHealth{notApplied: "backend health is not applied by gateway nodes gw-b"},
		},
		{
			name:          "a rule without a healthCheck ignores health",
			noHealthCheck: true,
			gate:          applied,
			sick:          decision(bgpv1alpha1.BackendHealthUnhealthy),
			wantBackends:  []string{testHealthyAddr, testSickAddr},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := newHealthRule()
			if tt.noHealthCheck {
				rule.Spec.HealthCheck = nil
			}
			sick := healthBinding(rule, testSickAddr, tt.sick)
			if tt.staleSick {
				sick.Spec.VPCRef = "another-vpc"
			}
			bindings := serviceBindings{}
			for _, b := range []*bgpv1alpha1.ServiceVIPBinding{healthBinding(rule, testHealthyAddr, tt.healthy), sick} {
				bindings[b.Name] = b
			}

			dr, _, _, rh, err := buildDesiredRule(rule, []*cloudv1alpha1.VPCAttachment{newHealthAttachment()}, idx,
				nil, false, bindings, tt.gate, "")
			if err != nil {
				t.Fatalf("buildDesiredRule: %v", err)
			}
			if got := backendAddrs(dr.Backends); !slices.Equal(got, tt.wantBackends) {
				t.Errorf("backends = %v, want %v", got, tt.wantBackends)
			}
			if !slices.Equal(rh.unhealthy, tt.want.unhealthy) || rh.noneHealthy != tt.want.noneHealthy ||
				rh.notApplied != tt.want.notApplied {
				t.Errorf("health = %+v, want %+v", rh, tt.want)
			}
		})
	}
}

// TestBuildDesiredRule_HealthIsDeterministic: two gateways reading the same
// objects build the same backend list, whatever order the bindings were
// listed in.
func TestBuildDesiredRule_HealthIsDeterministic(t *testing.T) {
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	idx := &backendSIDIndex{
		routers:      map[string]*bgpv1alpha1.BGPRouter{backendRouter.Name: backendRouter},
		advs:         []*bgpv1alpha1.BGPAdvertisement{backendAdv},
		vrfInstances: map[string]*bgpv1alpha1.BGPVRFInstance{backendVRF.Name: backendVRF},
	}
	rule := newHealthRule()
	healthy := healthBinding(rule, testHealthyAddr, decision(bgpv1alpha1.BackendHealthHealthy))
	sick := healthBinding(rule, testSickAddr, decision(bgpv1alpha1.BackendHealthUnhealthy))
	attachments := []*cloudv1alpha1.VPCAttachment{newHealthAttachment()}

	a, _, _, _, errA := buildDesiredRule(rule, attachments, idx, nil, false,
		serviceBindings{healthy.Name: healthy, sick.Name: sick}, healthGate{apply: true}, "")
	b, _, _, _, errB := buildDesiredRule(rule, attachments, idx, nil, false,
		serviceBindings{sick.Name: sick, healthy.Name: healthy}, healthGate{apply: true}, "")
	if errA != nil || errB != nil {
		t.Fatalf("buildDesiredRule: %v, %v", errA, errB)
	}
	if !slices.Equal(a.Backends, b.Backends) {
		t.Errorf("backends differ: %v vs %v", a.Backends, b.Backends)
	}
}

// reconcileHealthGateway builds a testNodeGWA reconciler with BackendHealth
// on, over objs plus a second gateway testNodeGWB reporting gwBFilters.
func reconcileHealthGateway(
	t *testing.T, gwBFilters bool, objs ...client.Object,
) (client.Client, *fakeGatewayEngine, *NetworkGatewayReconciler) {
	t.Helper()
	scheme := newRuleTestScheme(t)
	gwB := newTestGateway(testNodeGWB)
	gwB.Status.BackendHealthFiltering = gwBFilters
	c := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{},
			&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(append(objs, newTestGateway(testNodeGWA), gwB)...).
		Build()
	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(c, scheme, engine, testNodeGWA)
	r.BackendHealth = true
	return c, engine, r
}

func healthFixtureObjects() []client.Object {
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newHealthRule()
	return []client.Object{
		newTestRouter(), backendRouter, backendAdv, backendVRF, newHealthAttachment(), rule,
		healthBinding(rule, testHealthyAddr, decision(bgpv1alpha1.BackendHealthHealthy)),
		healthBinding(rule, testSickAddr, decision(bgpv1alpha1.BackendHealthUnhealthy)),
	}
}

func setGatewayHealthFiltering(t *testing.T, c client.Client, node string, on bool) {
	t.Helper()
	gw := &bgpv1alpha1.NetworkGateway{}
	if err := c.Get(context.Background(), testRuleKey(node), gw); err != nil {
		t.Fatalf("get NetworkGateway %s: %v", node, err)
	}
	gw.Status.BackendHealthFiltering = on
	if err := c.Status().Update(context.Background(), gw); err != nil {
		t.Fatalf("update NetworkGateway %s status: %v", node, err)
	}
}

func engineBackends(engine *fakeGatewayEngine) []string {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return backendAddrs(engine.lastDesired.Rules[testNamespace+"/"+testRuleName].Backends)
}

func programmedFor(t *testing.T, c client.Client) *metav1.Condition {
	t.Helper()
	cond := meta.FindStatusCondition(ruleConditions(t, c, testRuleName), programmedConditionType(testNodeGWA))
	if cond == nil {
		t.Fatal("no Programmed condition for gw-a")
	}
	return cond
}

// TestGatewayHealth_AppliesOnlyWhenEveryGatewayFilters: a gateway applies
// health only while every NetworkGateway in the namespace reports it, reports
// that it does on its own NetworkGateway, and stops when a gateway stops
// reporting it, as an older gateway's status write does.
func TestGatewayHealth_AppliesOnlyWhenEveryGatewayFilters(t *testing.T) {
	c, engine, r := reconcileHealthGateway(t, false, healthFixtureObjects()...)

	runGatewayPass(t, r)
	gw := &bgpv1alpha1.NetworkGateway{}
	if err := c.Get(context.Background(), testRuleKey(testNodeGWA), gw); err != nil {
		t.Fatal(err)
	}
	if !gw.Status.BackendHealthFiltering {
		t.Error("gw-a does not report BackendHealthFiltering")
	}
	if got := engineBackends(engine); !slices.Equal(got, []string{testHealthyAddr, testSickAddr}) {
		t.Errorf("backends with gw-b not filtering = %v, want both", got)
	}
	if cond := programmedFor(t, c); cond.Status != metav1.ConditionTrue ||
		cond.Reason != reasonHealthChecksNotApplied || !strings.Contains(cond.Message, testNodeGWB) {
		t.Errorf("Programmed = %s/%s %q, want True/%s naming %s",
			cond.Status, cond.Reason, cond.Message, reasonHealthChecksNotApplied, testNodeGWB)
	}

	setGatewayHealthFiltering(t, c, testNodeGWB, true)
	runGatewayPass(t, r)
	if got := engineBackends(engine); !slices.Equal(got, []string{testHealthyAddr}) {
		t.Errorf("backends with every gateway filtering = %v, want only %s", got, testHealthyAddr)
	}
	if cond := programmedFor(t, c); cond.Status != metav1.ConditionTrue || cond.Reason != reasonBackendsUnhealthy ||
		!strings.Contains(cond.Message, testSickAddr) {
		t.Errorf("Programmed = %s/%s %q, want True/%s naming %s",
			cond.Status, cond.Reason, cond.Message, reasonBackendsUnhealthy, testSickAddr)
	}

	setGatewayHealthFiltering(t, c, testNodeGWB, false)
	runGatewayPass(t, r)
	if got := engineBackends(engine); !slices.Equal(got, []string{testHealthyAddr, testSickAddr}) {
		t.Errorf("backends after gw-b stopped filtering = %v, want both", got)
	}
}

// TestGatewayHealth_OffReportsNotApplied: with BackendHealth off, the gateway
// reports no filtering and leaves every backend in a rule with a healthCheck.
func TestGatewayHealth_OffReportsNotApplied(t *testing.T) {
	c, engine, r := reconcileHealthGateway(t, true, healthFixtureObjects()...)
	r.BackendHealth = false

	runGatewayPass(t, r)

	gw := &bgpv1alpha1.NetworkGateway{}
	if err := c.Get(context.Background(), testRuleKey(testNodeGWA), gw); err != nil {
		t.Fatal(err)
	}
	if gw.Status.BackendHealthFiltering {
		t.Error("gw-a reports BackendHealthFiltering with BackendHealth off")
	}
	if got := engineBackends(engine); !slices.Equal(got, []string{testHealthyAddr, testSickAddr}) {
		t.Errorf("backends = %v, want both", got)
	}
	if cond := programmedFor(t, c); cond.Reason != reasonHealthChecksNotApplied {
		t.Errorf("Programmed reason = %s, want %s", cond.Reason, reasonHealthChecksNotApplied)
	}
}

// TestGatewayHealth_AllUnhealthyKeepsServing: every backend Unhealthy keeps all
// of them and keeps the rule advertised.
func TestGatewayHealth_AllUnhealthyKeepsServing(t *testing.T) {
	objs := healthFixtureObjects()
	for _, o := range objs {
		if b, ok := o.(*bgpv1alpha1.ServiceVIPBinding); ok {
			b.Status.Health = decision(bgpv1alpha1.BackendHealthUnhealthy)
		}
	}
	c, engine, r := reconcileHealthGateway(t, true, objs...)

	runGatewayPass(t, r)
	// gw-a reports filtering after its first pass; the second applies it.
	runGatewayPass(t, r)

	if got := engineBackends(engine); !slices.Equal(got, []string{testHealthyAddr, testSickAddr}) {
		t.Errorf("backends = %v, want both kept", got)
	}
	if cond := programmedFor(t, c); cond.Status != metav1.ConditionTrue || cond.Reason != reasonNoHealthyBackends {
		t.Errorf("Programmed = %s/%s, want True/%s", cond.Status, cond.Reason, reasonNoHealthyBackends)
	}
	if _, ok := advertisedPrefixes(t, c, testRuleAdv); !ok {
		t.Error("the rule's VIP is not advertised while every backend is Unhealthy")
	}
}

// TestBindingReadinessChanged_Health: with health on, bindings of IPv6 VIPs
// pass and a change of status.health does, while an unrelated status write
// does not.
func TestBindingReadinessChanged_Health(t *testing.T) {
	rule := newHealthRule()
	v6 := healthBinding(rule, testSickAddr, nil)
	sick := v6.DeepCopy()
	sick.Status.Health = decision(bgpv1alpha1.BackendHealthUnhealthy)
	reworded := sick.DeepCopy()
	reworded.Status.Conditions = []metav1.Condition{{Type: "Other", Status: metav1.ConditionTrue}}

	on, off := bindingReadinessChanged(true), bindingReadinessChanged(false)
	for _, tc := range []struct {
		name string
		got  bool
		want bool
	}{
		{"CreateIPv6On", on.Create(event.CreateEvent{Object: v6}), true},
		{"CreateIPv6Off", off.Create(event.CreateEvent{Object: v6}), false},
		{"HealthChanged", on.Update(event.UpdateEvent{ObjectOld: v6, ObjectNew: sick}), true},
		{"UnrelatedStatus", on.Update(event.UpdateEvent{ObjectOld: sick, ObjectNew: reworded}), false},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: passed = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// TestGatewayHealthFilteringChanged: only a change in BackendHealthFiltering,
// a create or a delete re-queues the namespace's gateways.
func TestGatewayHealthFilteringChanged(t *testing.T) {
	p := gatewayHealthFilteringChanged()
	off := newTestGateway(testNodeGWB)
	on := off.DeepCopy()
	on.Status.BackendHealthFiltering = true
	conditioned := on.DeepCopy()
	conditioned.Status.Conditions = []metav1.Condition{
		{Type: bgpv1alpha1.ConditionTypeReady, Status: metav1.ConditionTrue},
	}

	if !p.Update(event.UpdateEvent{ObjectOld: off, ObjectNew: on}) {
		t.Error("BackendHealthFiltering turning on did not pass")
	}
	if p.Update(event.UpdateEvent{ObjectOld: on, ObjectNew: conditioned}) {
		t.Error("a condition-only update passed")
	}
	if !p.Create(event.CreateEvent{Object: off}) || !p.Delete(event.DeleteEvent{Object: off}) {
		t.Error("a create or delete did not pass")
	}
}
