// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.datum.net/galactic/internal/gateway"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// errAdvertisementWrite and errOrphanSweep are the injected failures the
// #365 regression tests below assert are surfaced rather than swallowed.
var (
	errAdvertisementWrite = errors.New("simulated BGPAdvertisement write failure")
	errOrphanSweep        = errors.New("simulated orphan sweep failure")
)

// fakeGatewayEngine records the EngineState passed to Reconcile so tests can
// assert on exactly which rules were included or excluded.
type fakeGatewayEngine struct {
	mu             sync.Mutex
	lastDesired    gateway.EngineState
	reconciled     int
	reconcileErr   error
	orphansErr     error
	stopped        bool
	generation     uint64
	orphansCutoffs []uint64

	// loadErrs fails the named rule keys with the given error, the way the
	// real engine reports a quota rejection or a datapath refusal.
	loadErrs map[string]string
}

func newFakeGatewayEngine() *fakeGatewayEngine {
	return &fakeGatewayEngine{}
}

func (f *fakeGatewayEngine) Reconcile(_ context.Context, desired gateway.EngineState) (gateway.EngineStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconciled++
	f.lastDesired = desired
	if f.reconcileErr != nil {
		return gateway.EngineStatus{}, f.reconcileErr
	}
	status := gateway.EngineStatus{Healthy: true}
	for key := range desired.Rules {
		if msg, ok := f.loadErrs[key]; ok {
			status.Healthy = false
			status.Rules = append(status.Rules, gateway.RuleStatus{Key: key, Applied: false, Error: msg})
			continue
		}
		status.Rules = append(status.Rules, gateway.RuleStatus{Key: key, Applied: true})
	}
	return status, nil
}

func (f *fakeGatewayEngine) DatapathGeneration() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.generation
}

func (f *fakeGatewayEngine) ReconcileOrphans(_ context.Context, _ gateway.EngineState, cutoff uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orphansCutoffs = append(f.orphansCutoffs, cutoff)
	return f.orphansErr
}

func (f *fakeGatewayEngine) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	return nil
}

// newIndexedClientBuilder returns a fake.ClientBuilder with the
// BGPRouterByTargetName index pre-registered, since
// NetworkGatewayReconciler.routerNameForNode relies on it via
// client.MatchingFields.
func newIndexedClientBuilder(scheme *runtime.Scheme) *fake.ClientBuilder {
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&bgpv1alpha1.BGPRouter{}, BGPRouterByTargetName, func(obj client.Object) []string {
			r, ok := obj.(*bgpv1alpha1.BGPRouter)
			if !ok {
				return nil
			}
			return []string{r.Spec.TargetRef.Name}
		})
}

func acceptRule(rule *bgpv1alpha1.NetworkRule) {
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
		Type:   bgpv1alpha1.ConditionTypeAccepted,
		Status: metav1.ConditionTrue,
		Reason: bgpv1alpha1.AcceptedReasonOwnershipVerified,
	})
}

// newGatewayReconciler builds a NetworkGatewayReconciler wired to fakes,
// trimming the repeated multi-field struct literal out of every test below.
func newGatewayReconciler(
	c client.Client, scheme *runtime.Scheme, engine GatewayEngine, node string,
) *NetworkGatewayReconciler {
	return &NetworkGatewayReconciler{Client: c, Scheme: scheme, Engine: engine, NodeName: node}
}

// newTestRouter returns the BGPRouter targeting testNodeGWA, resolved
// through the
// BGPRouterByTargetName index newIndexedClientBuilder registers. Without
// one, routerNameForNode returns "" and Reconcile skips every
// BGPAdvertisement it would otherwise write.
func newTestRouter() *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRouterName},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: testNodeGWA},
			LocalASN:  65000,
			RouterID:  "1.1.1.1",
		},
	}
}

// gatewayReadyCondition returns testNodeGWA's NetworkGateway Ready
// condition, failing the test if the object or the condition is missing.
// Every caller reconciles testNodeGWA's own gateway, so this takes no node
// parameter of its own.
func gatewayReadyCondition(t *testing.T, c client.Client) *metav1.Condition {
	t.Helper()
	gw := &bgpv1alpha1.NetworkGateway{}
	if err := c.Get(context.Background(), testRuleKey(testNodeGWA), gw); err != nil {
		t.Fatalf("get NetworkGateway %s: %v", testNodeGWA, err)
	}
	cond := meta.FindStatusCondition(gw.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
	if cond == nil {
		t.Fatalf("NetworkGateway %s has no %s condition", testNodeGWA, bgpv1alpha1.ConditionTypeReady)
	}
	return cond
}

// ruleProgrammedCondition returns testNodeGWA's Programmed condition on the
// named NetworkRule, or nil when the rule carries none.
func ruleProgrammedCondition(t *testing.T, c client.Client, name string) *metav1.Condition {
	t.Helper()
	rule := &bgpv1alpha1.NetworkRule{}
	if err := c.Get(context.Background(), testRuleKey(name), rule); err != nil {
		t.Fatalf("get NetworkRule %s: %v", name, err)
	}
	return meta.FindStatusCondition(rule.Status.Conditions, programmedConditionType(testNodeGWA))
}

// assertRuleProgrammed fails the test unless testNodeGWA's Programmed
// condition on testRuleName has the given status and reason.
func assertRuleProgrammed(t *testing.T, c client.Client, status metav1.ConditionStatus, reason string) {
	t.Helper()
	name := testRuleName
	cond := ruleProgrammedCondition(t, c, name)
	if cond == nil {
		t.Fatalf("NetworkRule %s has no %s condition", name, programmedConditionType(testNodeGWA))
	}
	if cond.Status != status || cond.Reason != reason {
		t.Errorf("NetworkRule %s %s = %s/%s, want %s/%s",
			name, cond.Type, cond.Status, cond.Reason, status, reason)
	}
}

func TestNetworkGatewayReconciler_SkipsNonMatchingNode(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gw := newTestGateway(testNodeGWA)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gw).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, "gw-other")
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if engine.reconciled != 0 {
		t.Fatal("engine should not be reconciled for a NetworkGateway targeting a different node")
	}
}

func TestNetworkGatewayReconciler_StopsEngineOnNotFound(t *testing.T) {
	scheme := newRuleTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if !engine.stopped {
		t.Fatal("engine.Stop was not called for a deleted NetworkGateway")
	}
}

// TestNetworkGatewayReconciler_IgnoresDeletionOfOtherNodesGateway is the
// regression test for #364: every gateway node's process reconciles every
// NetworkGateway in the namespace (SetupWithManager has no predicate), so
// deleting gw-b's NetworkGateway also enqueues a NotFound reconcile for
// gw-a's process. gw-a's own NetworkGateway is untouched, so its engine
// must keep running.
func TestNetworkGatewayReconciler_IgnoresDeletionOfOtherNodesGateway(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA) // this node's own gateway; still exists

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)

	// gw-b's NetworkGateway was deleted (it never existed in this fixture
	// -- only its NamespacedName is needed to reconstruct the NotFound
	// reconcile gw-a's own process would receive for it).
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWB)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if engine.stopped {
		t.Fatal("engine.Stop was called for another node's deleted NetworkGateway; " +
			"this node's own NetworkGateway is untouched and its engine must keep running")
	}
}

// TestNetworkGatewayReconciler_BuildsDesiredStateForAcceptedRules covers
// DSR's anycast model directly: every accepted, non-deleting NetworkRule in
// the namespace goes into desired state, with no primary/secondary
// distinction to gate on: every gateway node in a PoP serves every accepted
// rule identically.
func TestNetworkGatewayReconciler_BuildsDesiredStateForAcceptedRules(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	gwB := newTestGateway(testNodeGWB)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	// ruleB resolves the identical backend address under a different
	// tenant (vpc-2) -- its own BGPAdvertisement/BGPVRFInstance, same
	// shared physical router, proving the two rules' backend resolutions
	// don't need (or get) cross-tenant help from one another.
	_, backendAdv2, backendVRF2 := newBackendFixtures("vpc-2")

	ruleA := newTestRule("rule-a", "vpc-1", testVIP)
	acceptRule(ruleA)

	ruleB := newTestRule("rule-b", "vpc-2", "203.0.113.6")
	acceptRule(ruleB)

	notAccepted := newTestRule("not-accepted", "vpc-4", "203.0.113.8")
	// No Accepted condition set -- must be excluded.

	// No BGPAdvertisement carries its label, so nothing is left to withdraw
	// and this node never loaded it: it is excluded straight away. A deleting
	// rule whose route is still advertised drains instead; see
	// TestNetworkGatewayReconciler_DrainsDeletedRuleUntilWithdrawn.
	deleting := newTestRule("deleting", "vpc-5", "203.0.113.9")
	acceptRule(deleting)
	deleting.Finalizers = []string{networkRuleFinalizer}
	now := metav1.Now()
	deleting.DeletionTimestamp = &now

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, gwB, backendRouter, backendAdv, backendVRF, backendAdv2, backendVRF2,
			ruleA, ruleB, notAccepted, deleting).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	if engine.reconciled != 1 {
		t.Fatalf("engine.Reconcile called %d times, want 1", engine.reconciled)
	}
	if len(engine.lastDesired.Rules) != 2 {
		t.Fatalf("desired rules = %d, want 2 (rule-a, rule-b); got %+v",
			len(engine.lastDesired.Rules), engine.lastDesired.Rules)
	}

	if _, ok := engine.lastDesired.Rules[testNamespace+"/rule-a"]; !ok {
		t.Error("rule-a missing from desired state")
	}
	if _, ok := engine.lastDesired.Rules[testNamespace+"/rule-b"]; !ok {
		t.Error("rule-b missing from desired state")
	}

	if len(engine.orphansCutoffs) != 1 {
		t.Fatalf("ReconcileOrphans called %d times, want 1", len(engine.orphansCutoffs))
	}
}

// TestNetworkGatewayReconciler_ExcludesRuleWithUnresolvableBackend verifies
// that a rule whose backend address matches no BGPAdvertisement (design
// plan decision #5's uSID resolution) is excluded from desired state
// rather than failing the whole reconcile -- mirroring how a malformed VIP
// address is handled.
func TestNetworkGatewayReconciler_ExcludesRuleWithUnresolvableBackend(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	// No backend router/advertisement fixtures: testBackendAddr resolves
	// against nothing.
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, rule).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(engine.lastDesired.Rules) != 0 {
		t.Fatalf("desired rules = %d, want 0 (backend unresolvable); got %+v",
			len(engine.lastDesired.Rules), engine.lastDesired.Rules)
	}
	assertRuleProgrammed(t, fakeClient, metav1.ConditionFalse, reasonInvalidRule)
}

// TestNetworkGatewayReconciler_ServesThroughResolvedBackends covers #713: a
// rule with one backend whose uSID does not resolve, as while a backend pod is
// recreated, keeps serving and stays advertised through the backends that do
// resolve, and its Programmed condition names the one left out.
func TestNetworkGatewayReconciler_ServesThroughResolvedBackends(t *testing.T) {
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	// Outside testBackendPrefix, so it resolves against nothing.
	rule.Spec.Backends = append(rule.Spec.Backends, bgpv1alpha1.NetworkRuleBackend{Address: "192.0.2.99", Port: 8443})
	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF, rule).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	dr, ok := engine.lastDesired.Rules[testNamespace+"/"+testRuleName]
	if !ok {
		t.Fatalf("rule missing from desired state although backend %s resolves", testBackendAddr)
	}
	if len(dr.Backends) != 1 || dr.Backends[0].Address != netip.MustParseAddr(testBackendAddr) {
		t.Fatalf("desired backends = %+v, want only %s", dr.Backends, testBackendAddr)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), adv); err != nil {
		t.Fatalf("get BGPAdvertisement %s: %v (the rule still serves, so it must stay advertised)", testRuleAdvV4, err)
	}

	assertRuleProgrammed(t, fakeClient, metav1.ConditionTrue, reasonBackendsUnresolved)
	cond := ruleProgrammedCondition(t, fakeClient, testRuleName)
	if !strings.Contains(cond.Message, "1 of 2 backends") || !strings.Contains(cond.Message, "192.0.2.99:8443") {
		t.Errorf("Programmed message = %q, want it to count 1 of 2 backends and name 192.0.2.99:8443", cond.Message)
	}
}

// TestBuildDesiredRule_BackendResolution covers which backend failures leave
// a backend out and which fail the whole rule.
func TestBuildDesiredRule_BackendResolution(t *testing.T) {
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	idx := &backendSIDIndex{
		routers:      map[string]*bgpv1alpha1.BGPRouter{backendRouter.Name: backendRouter},
		advs:         []*bgpv1alpha1.BGPAdvertisement{backendAdv},
		vrfInstances: map[string]*bgpv1alpha1.BGPVRFInstance{backendVRF.Name: backendVRF},
	}

	tests := []struct {
		name           string
		backends       []string
		wantErr        bool
		wantBackends   int
		wantUnresolved []string
	}{
		{name: "all resolve", backends: []string{testBackendAddr, "10.0.0.2"}, wantBackends: 2},
		{
			name: "some unresolved", backends: []string{testBackendAddr, "198.51.100.1", "2001:db8::1"},
			wantBackends: 1, wantUnresolved: []string{"198.51.100.1:8443", "[2001:db8::1]:8443"},
		},
		{name: "none resolve", backends: []string{"198.51.100.1", "198.51.100.2"}, wantErr: true},
		{name: "malformed address", backends: []string{testBackendAddr, "not-an-ip"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := newTestRule(testRuleName, "vpc-1", testVIP)
			rule.Spec.Backends = nil
			for _, b := range tt.backends {
				rule.Spec.Backends = append(rule.Spec.Backends, bgpv1alpha1.NetworkRuleBackend{Address: b, Port: 8443})
			}

			dr, unresolved, err := buildDesiredRule(rule, idx)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("buildDesiredRule: err = nil, want an error; got %+v", dr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildDesiredRule: %v", err)
			}
			if len(dr.Backends) != tt.wantBackends {
				t.Errorf("backends = %d, want %d", len(dr.Backends), tt.wantBackends)
			}
			if !slices.Equal(unresolved, tt.wantUnresolved) {
				t.Errorf("unresolved = %v, want %v", unresolved, tt.wantUnresolved)
			}
		})
	}
}

func TestNetworkGatewayReconciler_SkipsBGPAdvertisementWiringWithoutRouter(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, backendRouter, backendAdv, backendVRF, rule).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := fakeClient.List(context.Background(), advList); err != nil {
		t.Fatalf("list BGPAdvertisements: %v", err)
	}
	// Only backendAdv should exist -- no rule VIP advertisement without a
	// BGPRouter targeting this node.
	if len(advList.Items) != 1 {
		t.Fatalf("expected only the pre-seeded backend BGPAdvertisement, got %d", len(advList.Items))
	}
}

// TestNetworkGatewayReconciler_CreatesBGPAdvertisement covers the anycast
// BGPAdvertisement shape directly: no LocalPreference is set at all, since
// every gateway node's route is equally preferred by construction (see
// networkgateway_controller.go's applyBGPAdvertisements doc comment).
func TestNetworkGatewayReconciler_CreatesBGPAdvertisement(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	gwB := newTestGateway(testNodeGWB)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	router := newTestRouter()
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)
	rule.UID = testRuleUID

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, gwB, router, backendRouter, backendAdv, backendVRF, rule).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), adv); err != nil {
		t.Fatalf("get BGPAdvertisement %s: %v", testRuleAdvV4, err)
	}
	if adv.Spec.RouterRef.Name != testRouterName {
		t.Errorf("RouterRef.Name = %q, want %q", adv.Spec.RouterRef.Name, testRouterName)
	}
	if adv.Spec.AddressFamily.AFI != bgpv1alpha1.AFIL2VPN || adv.Spec.AddressFamily.SAFI != bgpv1alpha1.SAFIEVPN {
		t.Errorf("AddressFamily = %+v, want l2vpn/evpn", adv.Spec.AddressFamily)
	}
	if adv.Spec.LocalPreference != nil {
		t.Errorf("LocalPreference = %v, want nil (every gateway node's route is equally preferred under DSR)",
			*adv.Spec.LocalPreference)
	}
	if len(adv.Spec.Prefixes) != 1 || adv.Spec.Prefixes[0] != testVIPPrefix {
		t.Errorf("Prefixes = %v, want [%s]", adv.Spec.Prefixes, testVIPPrefix)
	}
	if got := adv.Labels[networkRuleLabel]; got != testRuleName {
		t.Errorf("Labels[%s] = %q, want %q (networkrule_controller.go's teardown depends on this)",
			networkRuleLabel, got, testRuleName)
	}
	assertRuleOwnerReference(t, adv)
	if got := adv.Labels[gatewayNodeLabel]; got != testNodeGWA {
		t.Errorf("Labels[%s] = %q, want %q (withdrawNodeAdvertisements selects on this)",
			gatewayNodeLabel, got, testNodeGWA)
	}
	assertRuleProgrammed(t, fakeClient, metav1.ConditionTrue, reasonProgrammed)
}

// TestNetworkGatewayReconciler_BackfillsLabelOnExistingAdvertisement covers
// applyBGPAdvertisements's update path self-healing an advertisement that
// was created before networkRuleLabel (issue #367) or gatewayNodeLabel
// (issue #714) existed — without this, an advertisement from an older
// release would stay permanently invisible to NetworkRuleReconciler's
// teardown List and to withdrawNodeAdvertisements's. The owner reference to
// the rule (#715) is backfilled the same way, so garbage collection covers it
// too.
func TestNetworkGatewayReconciler_BackfillsLabelOnExistingAdvertisement(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	router := newTestRouter()
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	acceptRule(rule)
	rule.UID = testRuleUID

	preexisting := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRuleAdvV4}, // no label
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testVIPPrefix},
		},
	}

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, router, backendRouter, backendAdv, backendVRF, rule, preexisting).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), adv); err != nil {
		t.Fatalf("get BGPAdvertisement %s: %v", testRuleAdvV4, err)
	}
	if got := adv.Labels[networkRuleLabel]; got != testRuleName {
		t.Errorf("Labels[%s] = %q, want %q (backfill on update path)", networkRuleLabel, got, testRuleName)
	}
	assertRuleOwnerReference(t, adv)
	if got := adv.Labels[gatewayNodeLabel]; got != testNodeGWA {
		t.Errorf("Labels[%s] = %q, want %q (backfill on update path)", gatewayNodeLabel, got, testNodeGWA)
	}
}

// TestNetworkGatewayReconciler_AdvertisementFailureSurfaces is the
// regression test for #365: BGPAdvertisement write failures used to be
// logged and dropped, so a node that had advertised nothing still reported
// Ready=True/EngineHealthy (the condition was computed from the engine
// result alone) and Reconcile returned nil, so nothing retried either.
func TestNetworkGatewayReconciler_AdvertisementFailureSurfaces(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	router := newTestRouter()
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, router, backendRouter, backendAdv, backendVRF, rule).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(
				ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption,
			) error {
				if _, ok := obj.(*bgpv1alpha1.BGPAdvertisement); ok {
					return errAdvertisementWrite
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	_, err := r.Reconcile(context.Background(), req)
	if err == nil {
		t.Fatal("Reconcile returned nil for a failed BGPAdvertisement write; the failure must be retried")
	}
	if !errors.Is(err, errAdvertisementWrite) {
		t.Errorf("Reconcile error = %v, want it to wrap %v", err, errAdvertisementWrite)
	}

	cond := gatewayReadyCondition(t, fakeClient)
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("Ready status = %s, want %s", cond.Status, metav1.ConditionFalse)
	}
	if cond.Reason != reasonAdvertisementFailed {
		t.Errorf("Ready reason = %q, want %q", cond.Reason, reasonAdvertisementFailed)
	}
	if !strings.Contains(cond.Message, testRuleName) {
		t.Errorf("Ready message = %q, want it to name the failing NetworkRule %q", cond.Message, testRuleName)
	}
}

// TestNetworkGatewayReconciler_ReportsEngineHealthyOnCleanPass is the
// other half of #365: with every advertisement written, the node still
// reports Ready=True/EngineHealthy and Reconcile returns nil.
func TestNetworkGatewayReconciler_ReportsEngineHealthyOnCleanPass(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	router := newTestRouter()
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, router, backendRouter, backendAdv, backendVRF, rule).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), adv); err != nil {
		t.Fatalf("get BGPAdvertisement %s: %v", testRuleAdvV4, err)
	}

	cond := gatewayReadyCondition(t, fakeClient)
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("Ready status = %s, want %s", cond.Status, metav1.ConditionTrue)
	}
	if cond.Reason != reasonEngineHealthy {
		t.Errorf("Ready reason = %q, want %q", cond.Reason, reasonEngineHealthy)
	}
	assertRuleProgrammed(t, fakeClient, metav1.ConditionTrue, reasonProgrammed)
}

// errLoadQuota is the load failure the #712 regression tests make the fake
// engine report.
const errLoadQuota = "rule exceeds its per-tenant quota"

// TestNetworkGatewayReconciler_DoesNotAdvertiseUnloadedRule is the
// regression test for #712: a rule the engine refused to load must not be
// advertised from this node, and its status must name the failure.
func TestNetworkGatewayReconciler_DoesNotAdvertiseUnloadedRule(t *testing.T) {
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF, rule).
		Build()

	engine := newFakeGatewayEngine()
	engine.loadErrs = map[string]string{testNamespace + "/" + testRuleName: errLoadQuota}
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), adv); !apierrors.IsNotFound(err) {
		t.Fatalf("get BGPAdvertisement %s: err = %v, want NotFound (the rule never loaded); prefixes %v",
			testRuleAdvV4, err, adv.Spec.Prefixes)
	}

	assertRuleProgrammed(t, fakeClient, metav1.ConditionFalse, reasonLoadFailed)
	if cond := ruleProgrammedCondition(t, fakeClient, testRuleName); !strings.Contains(cond.Message, errLoadQuota) {
		t.Errorf("Programmed message = %q, want it to name the failure %q", cond.Message, errLoadQuota)
	}

	ready := gatewayReadyCondition(t, fakeClient)
	if ready.Reason != reasonEngineDegraded || !strings.Contains(ready.Message, testRuleName) {
		t.Errorf("Ready = %s/%q, want EngineDegraded naming %s", ready.Reason, ready.Message, testRuleName)
	}
	if key := testNamespace + "/" + testRuleName; !strings.Contains(ready.Message, key) {
		t.Errorf("Ready message = %q, want it to name the failed rule key %q", ready.Message, key)
	}
}

// TestNetworkGatewayReconciler_WithdrawsRuleThatStopsLoading covers a rule
// that was advertised and then fails to load: its route must be withdrawn,
// and its Programmed condition must flip to False.
func TestNetworkGatewayReconciler_WithdrawsRuleThatStopsLoading(t *testing.T) {
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF, rule).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("first Reconcile: unexpected error: %v", err)
	}
	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), adv); err != nil {
		t.Fatalf("get BGPAdvertisement %s after a clean pass: %v", testRuleAdvV4, err)
	}
	assertRuleProgrammed(t, fakeClient, metav1.ConditionTrue, reasonProgrammed)

	engine.loadErrs = map[string]string{testNamespace + "/" + testRuleName: errLoadQuota}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("second Reconcile: unexpected error: %v", err)
	}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), adv); !apierrors.IsNotFound(err) {
		t.Fatalf("get BGPAdvertisement %s: err = %v, want NotFound (the rule stopped loading)", testRuleAdvV4, err)
	}
	assertRuleProgrammed(t, fakeClient, metav1.ConditionFalse, reasonLoadFailed)
}

// TestNetworkGatewayReconciler_WithdrawsRuleThatStopsBuilding covers a rule
// that was advertised and then can no longer be built, here because its
// backend's uSID stops resolving. The engine drops it from the datapath, so
// its route must go too.
func TestNetworkGatewayReconciler_WithdrawsRuleThatStopsBuilding(t *testing.T) {
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)
	stale := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testRuleAdvV4,
			Labels:    map[string]string{networkRuleLabel: testRuleName, gatewayNodeLabel: testNodeGWA},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testVIPPrefix},
		},
	}

	// No backend fixtures: the backend no longer resolves.
	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), rule, stale).
		Build()

	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleAdvV4), adv); !apierrors.IsNotFound(err) {
		t.Fatalf("get BGPAdvertisement %s: err = %v, want NotFound (the rule no longer builds)", testRuleAdvV4, err)
	}
	assertRuleProgrammed(t, fakeClient, metav1.ConditionFalse, reasonInvalidRule)
}

// TestNetworkGatewayReconciler_ReturnsOrphanSweepFailure covers the third
// swallowed error from #365. The sweep is crash recovery, so its failure
// must be retried -- and the status write that precedes it still has to
// land, hence the Ready assertion.
func TestNetworkGatewayReconciler_ReturnsOrphanSweepFailure(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA).
		Build()

	engine := newFakeGatewayEngine()
	engine.orphansErr = errOrphanSweep
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	_, err := r.Reconcile(context.Background(), req)
	if err == nil {
		t.Fatal("Reconcile returned nil for a failed orphan sweep; the sweep must be retried")
	}
	if !errors.Is(err, errOrphanSweep) {
		t.Errorf("Reconcile error = %v, want it to wrap %v", err, errOrphanSweep)
	}

	cond := gatewayReadyCondition(t, fakeClient)
	if cond.Reason != reasonEngineHealthy {
		t.Errorf("Ready reason = %q, want %q (status is written before the sweep runs)",
			cond.Reason, reasonEngineHealthy)
	}
}

// newAdvertisement returns a minimal BGPAdvertisement fixture, named and
// namespaced only, with no labels: an advertisement from before the labels
// existed, or one the CNI wrote.
func newAdvertisement(name string) *bgpv1alpha1.BGPAdvertisement {
	return &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
	}
}

// newNodeAdvertisement returns a BGPAdvertisement fixture shaped like one
// applyBGPAdvertisements creates on node for rule: named by
// ruleAdvertisementName and carrying networkRuleLabel and gatewayNodeLabel,
// which is all withdrawNodeAdvertisements looks at.
func newNodeAdvertisement(rule, node, family string) *bgpv1alpha1.BGPAdvertisement {
	adv := newAdvertisement(ruleAdvertisementName(rule, node, family))
	adv.Labels = map[string]string{networkRuleLabel: rule, gatewayNodeLabel: gatewayNodeLabelValue(node)}
	return adv
}

// TestNetworkGatewayReconciler_WithdrawsAdvertisementsForDepartedGatewayNode
// is the regression test for #406: gw-b's NetworkGateway is deleted while
// gw-b's own per-rule BGPAdvertisement routes are still around. gw-a's
// process -- the only one left to react, since gw-b's own process is
// presumably already gone -- must withdraw every one of them on the NotFound
// reconcile it receives for gw-b's deletion, without touching gw-a's own
// advertisements for the same rule.
func TestNetworkGatewayReconciler_WithdrawsAdvertisementsForDepartedGatewayNode(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA) // gw-a's own gateway; still exists

	ruleV4 := newNodeAdvertisement(testRuleName, testNodeGWB, "v4")
	ruleV6 := newNodeAdvertisement(testRuleName, testNodeGWB, "v6")
	otherRuleV4 := newNodeAdvertisement("other-rule", testNodeGWB, "v4")
	survivorAdv := newNodeAdvertisement(testRuleName, testNodeGWA, "v4")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, ruleV4, ruleV6, otherRuleV4, survivorAdv).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)

	// gw-b's NetworkGateway was deleted (it never existed in this fixture
	// -- only its NamespacedName is needed to reconstruct the NotFound
	// reconcile gw-a's own process would receive for it, exactly like
	// TestNetworkGatewayReconciler_IgnoresDeletionOfOtherNodesGateway).
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWB)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	ctx := context.Background()
	for _, gone := range []*bgpv1alpha1.BGPAdvertisement{ruleV4, ruleV6, otherRuleV4} {
		err := fakeClient.Get(ctx, testRuleKey(gone.Name), &bgpv1alpha1.BGPAdvertisement{})
		if !apierrors.IsNotFound(err) {
			t.Errorf("BGPAdvertisement %s still exists (err=%v), want withdrawn with gw-b", gone.Name, err)
		}
	}
	if err := fakeClient.Get(ctx, testRuleKey(survivorAdv.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("gw-a's own BGPAdvertisement %s was removed: %v", survivorAdv.Name, err)
	}
}

// TestNetworkGatewayReconciler_DepartedNodeLeavesSuffixSharingNodesAlone is
// the regression test for #714: removing node "edge-1" used to withdraw node
// "east-edge-1"'s advertisements, and a CNI-written one, because unlabelled
// advertisements were matched on the "-edge-1-v4"/"-v6" name suffix alone.
// Only advertisements labelled for edge-1 may go.
func TestNetworkGatewayReconciler_DepartedNodeLeavesSuffixSharingNodesAlone(t *testing.T) {
	const (
		departed  = "edge-1"
		surviving = "east-edge-1"
	)
	scheme := newRuleTestScheme(t)

	departedV4 := newNodeAdvertisement(testRuleName, departed, "v4")
	departedV6 := newNodeAdvertisement(testRuleName, departed, "v6")
	survivorV4 := newNodeAdvertisement(testRuleName, surviving, "v4")
	survivorV6 := newNodeAdvertisement(testRuleName, surviving, "v6")
	unlabelledSurvivor := newAdvertisement("rulex-" + surviving + "-v4")
	cniAdv := newAdvertisement("vpc0000001-att0000001-" + surviving + "-v4")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(surviving),
			departedV4, departedV6, survivorV4, survivorV6, unlabelledSurvivor, cniAdv).
		Build()

	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), surviving)
	req := ctrl.Request{NamespacedName: testRuleKey(departed)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	ctx := context.Background()
	for _, gone := range []*bgpv1alpha1.BGPAdvertisement{departedV4, departedV6} {
		err := fakeClient.Get(ctx, testRuleKey(gone.Name), &bgpv1alpha1.BGPAdvertisement{})
		if !apierrors.IsNotFound(err) {
			t.Errorf("BGPAdvertisement %s still exists (err=%v), want withdrawn with %s", gone.Name, err, departed)
		}
	}
	for _, kept := range []*bgpv1alpha1.BGPAdvertisement{survivorV4, survivorV6, unlabelledSurvivor, cniAdv} {
		if err := fakeClient.Get(ctx, testRuleKey(kept.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
			t.Errorf("BGPAdvertisement %s was withdrawn with %s: %v", kept.Name, departed, err)
		}
	}
}

// TestNetworkGatewayReconciler_WithdrawsAdvertisementsForLongNamedNode covers
// a node name longer than the 63 characters a label value allows, an FQDN
// here. Its advertisements carry the shortened gatewayNodeLabelValue form, and
// withdrawal must select on that same form, or they would never go.
func TestNetworkGatewayReconciler_WithdrawsAdvertisementsForLongNamedNode(t *testing.T) {
	departed := testLongNodeName("a")
	surviving := testLongNodeName("b")
	scheme := newRuleTestScheme(t)

	departedV4 := newNodeAdvertisement(testRuleName, departed, "v4")
	survivorV4 := newNodeAdvertisement(testRuleName, surviving, "v4")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), departedV4, survivorV4).
		Build()

	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(departed)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	ctx := context.Background()
	err := fakeClient.Get(ctx, testRuleKey(departedV4.Name), &bgpv1alpha1.BGPAdvertisement{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("BGPAdvertisement %s still exists (err=%v), want withdrawn with its node", departedV4.Name, err)
	}
	if err := fakeClient.Get(ctx, testRuleKey(survivorV4.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("BGPAdvertisement %s of another long-named node was withdrawn: %v", survivorV4.Name, err)
	}
}

// testLongNodeName returns a node name longer than a label value may be,
// distinct from any other built with a different tail but sharing a long
// common prefix with it.
func testLongNodeName(tail string) string {
	return strings.Repeat("edge.", 15) + tail + ".example.com"
}

// TestGatewayNodeLabelValue covers the node-name-to-label-value mapping
// applyBGPAdvertisements writes and withdrawNodeAdvertisements selects on.
func TestGatewayNodeLabelValue(t *testing.T) {
	if got := gatewayNodeLabelValue("edge-1"); got != "edge-1" {
		t.Errorf("gatewayNodeLabelValue(edge-1) = %q, want it unchanged", got)
	}
	exact := strings.Repeat("a", validation.LabelValueMaxLength)
	if got := gatewayNodeLabelValue(exact); got != exact {
		t.Errorf("gatewayNodeLabelValue(63 chars) = %q, want it unchanged", got)
	}

	a, b := testLongNodeName("a"), testLongNodeName("b")
	gotA, gotB := gatewayNodeLabelValue(a), gatewayNodeLabelValue(b)
	for name, got := range map[string]string{a: gotA, b: gotB} {
		if errs := validation.IsValidLabelValue(got); len(errs) != 0 {
			t.Errorf("gatewayNodeLabelValue(%s) = %q, not a valid label value: %v", name, got, errs)
		}
	}
	if again := gatewayNodeLabelValue(a); again != gotA {
		t.Errorf("gatewayNodeLabelValue is not deterministic: %q then %q", gotA, again)
	}
	if gotA == gotB {
		t.Errorf("gatewayNodeLabelValue(%s) and (%s) both = %q, want distinct", a, b, gotA)
	}

	// A cut that lands right after a "." or "-" must not leave the value
	// ending in it before the hash separator.
	dotted := strings.Repeat("x", validation.LabelValueMaxLength-12) + ".yyyyyyyyyy"
	if errs := validation.IsValidLabelValue(gatewayNodeLabelValue(dotted)); len(errs) != 0 {
		t.Errorf("gatewayNodeLabelValue(%s) is not a valid label value: %v", dotted, errs)
	}
}

// TestNetworkGatewayReconciler_WithdrawsAdvertisementsOnOwnDeletion covers
// the DeletionTimestamp-set branch (Reconcile observes its own
// NetworkGateway still present but terminating). Not known to be
// reachable in production today -- NetworkGateway carries no finalizer, so
// this branch would only fire if one is added later or another controller
// races the Get -- but it must stay correct regardless, and a finalizer is
// the only way the fake client (matching real apiserver behavior) keeps a
// deleted object visible with its DeletionTimestamp set at all.
func TestNetworkGatewayReconciler_WithdrawsAdvertisementsOnOwnDeletion(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	gwA.Finalizers = []string{"test.datum.net/hold-for-deletion"}
	now := metav1.Now()
	gwA.DeletionTimestamp = &now

	ruleV4 := newNodeAdvertisement(testRuleName, testNodeGWA, "v4")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, ruleV4).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	if !engine.stopped {
		t.Error("engine.Stop was not called for a terminating NetworkGateway")
	}
	ctx := context.Background()
	for _, gone := range []*bgpv1alpha1.BGPAdvertisement{ruleV4} {
		err := fakeClient.Get(ctx, testRuleKey(gone.Name), &bgpv1alpha1.BGPAdvertisement{})
		if !apierrors.IsNotFound(err) {
			t.Errorf("BGPAdvertisement %s still exists (err=%v), want withdrawn on own deletion", gone.Name, err)
		}
	}
	cond := gatewayReadyCondition(t, fakeClient)
	if cond.Reason != reasonTerminating {
		t.Errorf("Ready reason = %q, want %q", cond.Reason, reasonTerminating)
	}
}

// TestBroadcastToGatewayRequests_ListsEveryGatewayInNamespace covers the
// primitive SetupWithManager's BGPRouter/BGPAdvertisement/BGPVRFInstance
// watches build on (added to close a real startup race: buildBackendSIDIndex
// resolving a rule's backend before its owning BGPAdvertisement existed
// permanently failed that rule, since none of BGPRouter/BGPAdvertisement/
// BGPVRFInstance were watched before -- only a later, unrelated reconcile
// trigger happened to paper over it). One request per NetworkGateway in the
// given namespace, none for a different namespace.
func TestBroadcastToGatewayRequests_ListsEveryGatewayInNamespace(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	gwB := newTestGateway(testNodeGWB)
	otherNS := &bgpv1alpha1.NetworkGateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "gw-c"},
		Spec:       bgpv1alpha1.NetworkGatewaySpec{TargetRef: bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: "gw-c"}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gwA, gwB, otherNS).Build()

	reqs := broadcastToGatewayRequests(context.Background(), fakeClient, testNamespace, "BGPAdvertisement", "some-adv")

	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2 (one per NetworkGateway in %q, none from other-ns)", len(reqs), testNamespace)
	}
	got := map[string]bool{}
	for _, r := range reqs {
		if r.Namespace != testNamespace {
			t.Errorf("request namespace = %q, want %q", r.Namespace, testNamespace)
		}
		got[r.Name] = true
	}
	if !got[testNodeGWA] || !got[testNodeGWB] {
		t.Errorf("requests = %v, want both %q and %q", reqs, testNodeGWA, testNodeGWB)
	}
}

func TestRuleToGatewayRequests_UsesRuleNamespace(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gw := newTestGateway(testNodeGWA)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()
	rule := newTestRule(testRuleName, testVPCRef, testVIP)

	reqs := ruleToGatewayRequests(context.Background(), fakeClient, rule)

	if len(reqs) != 1 || reqs[0].Name != testNodeGWA {
		t.Errorf("reqs = %v, want exactly one request for %q", reqs, testNodeGWA)
	}
}

// TestRuleToGatewayRequests_WrongTypeReturnsNil covers
// EnqueueRequestsFromMapFunc's contract: the map function is only ever
// called with the watched type, but a defensive type assertion (rather
// than a panic-inducing cast) is what makes that safe to rely on.
func TestRuleToGatewayRequests_WrongTypeReturnsNil(t *testing.T) {
	if reqs := ruleToGatewayRequests(context.Background(), nil, &bgpv1alpha1.NetworkGateway{}); reqs != nil {
		t.Errorf("reqs = %v, want nil for a non-NetworkRule object", reqs)
	}
}

func TestPrefixesByFamily(t *testing.T) {
	vips := []netip.Addr{netip.MustParseAddr(testVIP), netip.MustParseAddr("2001:db8::1")}
	v4, v6 := prefixesByFamily(vips)
	if len(v4) != 1 || v4[0] != testVIPPrefix {
		t.Errorf("v4 = %v", v4)
	}
	if len(v6) != 1 || v6[0] != "2001:db8::1/128" {
		t.Errorf("v6 = %v", v6)
	}
}

// TestNetworkGatewayReconciler_DisabledWithdrawsAndSkipsTheEngine: a node with
// its datapath turned off withdraws its own VIP advertisements, leaves another
// node's alone, never drives the engine, and says why on Ready.
func TestNetworkGatewayReconciler_DisabledWithdrawsAndSkipsTheEngine(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	own := newNodeAdvertisement(testRuleName, testNodeGWA, "v6")
	other := newNodeAdvertisement(testRuleName, testNodeGWB, "v6")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(gwA, own, other).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	r.Disabled = true
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	if engine.reconciled != 0 {
		t.Errorf("engine reconciled %d times while disabled, want 0", engine.reconciled)
	}
	ctx := context.Background()
	if err := fakeClient.Get(ctx, testRuleKey(own.Name), &bgpv1alpha1.BGPAdvertisement{}); !apierrors.IsNotFound(err) {
		t.Errorf("own advertisement %s still exists (err=%v), want withdrawn", own.Name, err)
	}
	if err := fakeClient.Get(ctx, testRuleKey(other.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("another node's advertisement %s was touched: %v", other.Name, err)
	}
	cond := gatewayReadyCondition(t, fakeClient)
	if cond.Status != metav1.ConditionFalse || cond.Reason != reasonDatapathDisabled {
		t.Errorf("Ready = %v/%q, want False/%q", cond.Status, cond.Reason, reasonDatapathDisabled)
	}
}

// TestIsNodeAdvertisement_LabelledNamesMatchExactly: a disabled node "edge-1"
// withdraws its own advertisements on every reconcile, so it must never match
// another node's advertisement, labelled or not, or a CNI-written one that
// shares its name suffix (#714).
func TestIsNodeAdvertisement_LabelledNamesMatchExactly(t *testing.T) {
	labelled := func(name, rule, node string) *bgpv1alpha1.BGPAdvertisement {
		adv := newAdvertisement(name)
		adv.Labels = map[string]string{networkRuleLabel: rule, gatewayNodeLabel: gatewayNodeLabelValue(node)}
		return adv
	}
	ruleLabelOnly := newAdvertisement("rulex-edge-1-v4")
	ruleLabelOnly.Labels = map[string]string{networkRuleLabel: "rulex"}
	tests := []struct {
		name string
		adv  *bgpv1alpha1.BGPAdvertisement
		want bool
	}{
		{"own labelled v4", labelled(ruleAdvertisementName("rulex", "edge-1", "v4"), "rulex", "edge-1"), true},
		{"own labelled v6", labelled(ruleAdvertisementName("rulex", "edge-1", "v6"), "rulex", "edge-1"), true},
		{"own labelled legacy v4", labelled("rulex-edge-1-v4", "rulex", "edge-1"), true},
		{"own labelled legacy v6", labelled("rulex-edge-1-v6", "rulex", "edge-1"), true},
		{"other node sharing the suffix", labelled("rulex-pop-edge-1-v4", "rulex", "pop-edge-1"), false},
		{"node label but name for another node", labelled("rulex-pop-edge-1-v4", "rulex", "edge-1"), false},
		{
			"node label but hashed name for another pair",
			labelled(ruleAdvertisementName("rulex-pop", "edge-1", "v4"), "rulex", "edge-1"), false,
		},
		{"rule label without node label", ruleLabelOnly, false},
		{"unlabelled legacy name", newAdvertisement("rulex-edge-1-v6"), false},
		{"unlabelled other node sharing the suffix", newAdvertisement("rulex-east-edge-1-v4"), false},
		{"CNI-named sharing the suffix", newAdvertisement("vpc0000001-att0000001-east-edge-1-v4"), false},
		{"unrelated", labelled("rulex-edge-2-v4", "rulex", "edge-2"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNodeAdvertisement(tt.adv, "edge-1"); got != tt.want {
				t.Errorf("isNodeAdvertisement(%s, edge-1) = %v, want %v", tt.adv.Name, got, tt.want)
			}
		})
	}
}

// TestNetworkGatewayReconciler_ClearsDepartedNodeProgrammedCondition covers
// a gateway node leaving: its Programmed condition on every rule goes with
// its advertisements, and every other node's condition stays.
func TestNetworkGatewayReconciler_ClearsDepartedNodeProgrammedCondition(t *testing.T) {
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)
	for _, node := range []string{testNodeGWA, testNodeGWB} {
		meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
			Type: programmedConditionType(node), Status: metav1.ConditionTrue, Reason: reasonProgrammed,
		})
	}

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), rule).
		Build()

	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWB)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	got := &bgpv1alpha1.NetworkRule{}
	if err := fakeClient.Get(context.Background(), testRuleKey(testRuleName), got); err != nil {
		t.Fatalf("get NetworkRule %s: %v", testRuleName, err)
	}
	if meta.FindStatusCondition(got.Status.Conditions, programmedConditionType(testNodeGWB)) != nil {
		t.Errorf("departed node %s's condition is still on NetworkRule %s", testNodeGWB, testRuleName)
	}
	if meta.FindStatusCondition(got.Status.Conditions, programmedConditionType(testNodeGWA)) == nil {
		t.Errorf("surviving node %s's condition was removed from NetworkRule %s", testNodeGWA, testRuleName)
	}
}

// TestReadyConditionFor_CapsListedFailures asserts the Ready message names
// at most maxReadyFailures rules and counts the rest.
func TestReadyConditionFor_CapsListedFailures(t *testing.T) {
	total := maxReadyFailures + 5
	status := gateway.EngineStatus{Healthy: false}
	for i := range total {
		status.Rules = append(status.Rules, gateway.RuleStatus{Key: fmt.Sprintf("ns/rule-%02d", i), Error: "quota"})
	}

	cond := readyConditionFor(status, nil)
	if cond.Reason != reasonEngineDegraded {
		t.Fatalf("Reason = %q, want EngineDegraded", cond.Reason)
	}
	if got := strings.Count(cond.Message, ": quota"); got != maxReadyFailures {
		t.Errorf("message names %d failures, want %d: %q", got, maxReadyFailures, cond.Message)
	}
	if !strings.HasSuffix(cond.Message, " and 5 more") {
		t.Errorf("message = %q, want suffix %q", cond.Message, " and 5 more")
	}
	if strings.Contains(cond.Message, fmt.Sprintf("rule-%02d", maxReadyFailures)) {
		t.Errorf("message names a failure past the cap: %q", cond.Message)
	}

	status.Rules = status.Rules[:maxReadyFailures]
	if cond := readyConditionFor(status, nil); strings.Contains(cond.Message, " more") {
		t.Errorf("message = %q, want no count at the cap", cond.Message)
	}
}

// TestNetworkGatewayReconciler_RuleDeletedMidPassIsNotAnError covers a rule
// that is listed and then deleted before its status is written.
func TestNetworkGatewayReconciler_RuleDeletedMidPassIsNotAnError(t *testing.T) {
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF, rule).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
			) error {
				if _, ok := obj.(*bgpv1alpha1.NetworkRule); ok {
					return apierrors.NewNotFound(bgpv1alpha1.GroupVersion.WithResource("networkrules").GroupResource(), key.Name)
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: unexpected error for a rule deleted mid-pass: %v", err)
	}
}

// TestNetworkGatewayReconciler_UnchangedProgrammedConditionWritesNothing
// asserts a second pass over an unchanged rule makes no status write, since
// each write wakes every gateway node.
func TestNetworkGatewayReconciler_UnchangedProgrammedConditionWritesNothing(t *testing.T) {
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)

	var ruleWrites atomic.Int32
	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF, rule).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(
				ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption,
			) error {
				if _, ok := obj.(*bgpv1alpha1.NetworkRule); ok {
					ruleWrites.Add(1)
				}
				return c.SubResource(sub).Update(ctx, obj, opts...)
			},
		}).
		Build()

	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if got := ruleWrites.Load(); got != 1 {
		t.Fatalf("first pass wrote NetworkRule status %d times, want 1", got)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if got := ruleWrites.Load(); got != 1 {
		t.Errorf("unchanged second pass wrote NetworkRule status %d times in total, want 1", got)
	}
}

// TestRuleAdvertisementName covers the per-rule, per-node advertisement name:
// distinct for rule/node pairs whose "<rule>-<node>" concatenations match
// (#762), and a valid object name however long the inputs.
func TestRuleAdvertisementName(t *testing.T) {
	if a, b := ruleAdvertisementName("a-b", "c", "v4"), ruleAdvertisementName("a", "b-c", "v4"); a == b {
		t.Errorf("rule a-b on node c and rule a on node b-c both named %q", a)
	}
	if v4, v6 := ruleAdvertisementName("a", "b", "v4"), ruleAdvertisementName("a", "b", "v6"); v4 == v6 {
		t.Errorf("v4 and v6 both named %q", v4)
	}
	got := ruleAdvertisementName("rule-1", "gw-a", "v4")
	if again := ruleAdvertisementName("rule-1", "gw-a", "v4"); got != again {
		t.Errorf("ruleAdvertisementName is not deterministic: %q then %q", got, again)
	}
	if !strings.HasPrefix(got, "rule-1-gw-a-") || !strings.HasSuffix(got, "-v4") {
		t.Errorf("ruleAdvertisementName(rule-1, gw-a, v4) = %q, want a readable rule-1-gw-a- prefix and -v4 suffix", got)
	}

	longRule := strings.Repeat("r", validation.DNS1123SubdomainMaxLength)
	for _, tt := range []struct{ rule, node string }{
		{"rule-1", "gw-a"},
		{"rule-1", testLongNodeName("a")},
		{longRule, testLongNodeName("a")},
		// Cut lands on the dots of the node name, which must be trimmed.
		{strings.Repeat("r", 170), testLongNodeName("a")},
	} {
		for _, family := range []string{"v4", "v6"} {
			got := ruleAdvertisementName(tt.rule, tt.node, family)
			if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
				t.Errorf("ruleAdvertisementName(%d-char rule, %s, %s) = %q, not a valid object name: %v",
					len(tt.rule), tt.node, family, got, errs)
			}
		}
	}
	if a, b := ruleAdvertisementName(longRule+"a", "n", "v4"), ruleAdvertisementName(longRule+"b", "n", "v4"); a == b {
		t.Errorf("two long rule names sharing a prefix both named %q", a)
	}
}

// TestApplyBGPAdvertisements_DashedNamesStaySeparate is the regression test
// for #762: rule a-b on node c and rule a on node b-c were both named
// a-b-c-v4, so the two nodes overwrote one object, and withdrawing rule a
// from node b-c deleted rule a-b's route on node c.
func TestApplyBGPAdvertisements_DashedNamesStaySeparate(t *testing.T) {
	scheme := newRuleTestScheme(t)
	ruleAB := newTestRule("a-b", "vpc-1", "192.0.2.1")
	ruleAB.UID = "uid-a-b"
	ruleA := newTestRule("a", "vpc-1", "192.0.2.2")
	ruleA.UID = "uid-a"
	fakeClient := newIndexedClientBuilder(scheme).WithObjects(ruleAB, ruleA).Build()
	ctx := context.Background()

	desired := func(vip string) gateway.DesiredRule {
		return gateway.DesiredRule{VIPAddresses: []netip.Addr{netip.MustParseAddr(vip)}}
	}
	nodeC := newGatewayReconciler(fakeClient, scheme, nil, "c")
	nodeBC := newGatewayReconciler(fakeClient, scheme, nil, "b-c")
	if err := nodeC.applyBGPAdvertisements(ctx, ruleAB, desired("192.0.2.1"), testRouterName); err != nil {
		t.Fatalf("apply rule a-b on node c: %v", err)
	}
	if err := nodeBC.applyBGPAdvertisements(ctx, ruleA, desired("192.0.2.2"), testRouterName); err != nil {
		t.Fatalf("apply rule a on node b-c: %v", err)
	}

	abOnC := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(ctx, testRuleKey(ruleAdvertisementName("a-b", "c", "v4")), abOnC); err != nil {
		t.Fatalf("get rule a-b's advertisement on node c: %v", err)
	}
	if got := abOnC.Labels[networkRuleLabel]; got != "a-b" {
		t.Errorf("rule a-b's advertisement labelled for rule %q", got)
	}
	if got := abOnC.Labels[gatewayNodeLabel]; got != "c" {
		t.Errorf("rule a-b's advertisement labelled for node %q", got)
	}
	if len(abOnC.Spec.Prefixes) != 1 || abOnC.Spec.Prefixes[0] != "192.0.2.1/32" {
		t.Errorf("rule a-b's advertisement Prefixes = %v, want [192.0.2.1/32]", abOnC.Spec.Prefixes)
	}

	if err := withdrawRuleAdvertisements(ctx, fakeClient, ruleA, "b-c"); err != nil {
		t.Fatalf("withdraw rule a from node b-c: %v", err)
	}
	err := fakeClient.Get(ctx, testRuleKey(ruleAdvertisementName("a", "b-c", "v4")), &bgpv1alpha1.BGPAdvertisement{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("rule a's advertisement on node b-c: err = %v, want NotFound after withdrawal", err)
	}
	if err := fakeClient.Get(ctx, testRuleKey(abOnC.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("withdrawing rule a from node b-c removed rule a-b's advertisement on node c: %v", err)
	}
}

// TestApplyBGPAdvertisements_PrunesOlderAdvertisements covers the cleanup
// after the #762 rename: this node's advertisements under the old
// "<rule>-<node>-<family>" name, whether labelled as now or with
// networkRuleLabel alone as releases up to v0.5.3 wrote them, and one for a
// family the rule no longer has. Another node's old-style advertisement for
// the same rule must stay.
func TestApplyBGPAdvertisements_PrunesOlderAdvertisements(t *testing.T) {
	scheme := newRuleTestScheme(t)
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	rule.UID = testRuleUID

	ruleLabelOnly := func(name string) *bgpv1alpha1.BGPAdvertisement {
		adv := newAdvertisement(name)
		adv.Labels = map[string]string{networkRuleLabel: testRuleName}
		return adv
	}
	legacyV4 := ruleLabelOnly(legacyRuleAdvertisementName(testRuleName, testNodeGWA, "v4"))
	legacyV6 := newAdvertisement(legacyRuleAdvertisementName(testRuleName, testNodeGWA, "v6"))
	legacyV6.Labels = map[string]string{networkRuleLabel: testRuleName, gatewayNodeLabel: testNodeGWA}
	staleV6 := newNodeAdvertisement(testRuleName, testNodeGWA, "v6")
	otherNodeLegacy := ruleLabelOnly(legacyRuleAdvertisementName(testRuleName, testNodeGWB, "v4"))
	otherNodeV6 := newNodeAdvertisement(testRuleName, testNodeGWB, "v6")

	fakeClient := newIndexedClientBuilder(scheme).
		WithObjects(rule, legacyV4, legacyV6, staleV6, otherNodeLegacy, otherNodeV6).
		Build()
	ctx := context.Background()

	r := newGatewayReconciler(fakeClient, scheme, nil, testNodeGWA)
	desired := gateway.DesiredRule{VIPAddresses: []netip.Addr{netip.MustParseAddr(testVIP)}}
	if err := r.applyBGPAdvertisements(ctx, rule, desired, testRouterName); err != nil {
		t.Fatalf("applyBGPAdvertisements: %v", err)
	}

	if err := fakeClient.Get(ctx, testRuleKey(testRuleAdvV4), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("get BGPAdvertisement %s: %v", testRuleAdvV4, err)
	}
	for _, gone := range []*bgpv1alpha1.BGPAdvertisement{legacyV4, legacyV6, staleV6} {
		err := fakeClient.Get(ctx, testRuleKey(gone.Name), &bgpv1alpha1.BGPAdvertisement{})
		if !apierrors.IsNotFound(err) {
			t.Errorf("BGPAdvertisement %s: err = %v, want NotFound", gone.Name, err)
		}
	}
	for _, kept := range []*bgpv1alpha1.BGPAdvertisement{otherNodeLegacy, otherNodeV6} {
		if err := fakeClient.Get(ctx, testRuleKey(kept.Name), &bgpv1alpha1.BGPAdvertisement{}); err != nil {
			t.Errorf("node %s's BGPAdvertisement %s was removed: %v", testNodeGWB, kept.Name, err)
		}
	}
}
