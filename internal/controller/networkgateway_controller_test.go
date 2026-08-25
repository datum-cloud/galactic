// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
// assert on exactly which rules were included/excluded and at what
// local-pref.
type fakeGatewayEngine struct {
	mu             sync.Mutex
	lastDesired    gateway.EngineState
	reconciled     int
	reconcileErr   error
	orphansErr     error
	stopped        bool
	generation     uint64
	orphansCutoffs []uint64
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
	return gateway.EngineStatus{Healthy: true}, nil
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

func TestNetworkGatewayReconciler_SkipsNonMatchingNode(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gw := newTestGateway(testNodeGWA)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
// distinction to gate on (an earlier, Full-NAT-era version of this test,
// "...ForAcceptedAssignedRules", also required status.primaryNode to be
// set -- that field and the active-passive model it implemented no longer
// exist; every gateway node in a PoP now serves every accepted rule
// identically).
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

	deleting := newTestRule("deleting", "vpc-5", "203.0.113.9")
	acceptRule(deleting)
	deleting.Finalizers = []string{networkRuleFinalizer}
	now := metav1.Now()
	deleting.DeletionTimestamp = &now

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
}

func TestNetworkGatewayReconciler_SkipsBGPAdvertisementWiringWithoutRouter(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
// BGPAdvertisement shape directly: no LocalPreference is set at all (an
// earlier, Full-NAT-era version of this test,
// "...WithComputedLocalPref", asserted a computed primary/secondary
// preference value here — that model no longer exists; every gateway
// node's route is equally preferred by construction, see
// networkgateway_controller.go's applyBGPAdvertisements doc comment).
func TestNetworkGatewayReconciler_CreatesBGPAdvertisement(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	gwB := newTestGateway(testNodeGWB)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	router := newTestRouter()
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
}

// TestNetworkGatewayReconciler_BackfillsLabelOnExistingAdvertisement covers
// applyBGPAdvertisements's update path self-healing an advertisement that
// was created before networkRuleLabel existed (issue #367) — without this,
// an advertisement from an older release would stay permanently invisible
// to NetworkRuleReconciler's teardown List.
func TestNetworkGatewayReconciler_BackfillsLabelOnExistingAdvertisement(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	router := newTestRouter()
	rule := newTestRule(testRuleName, "vpc-1", testVIP)

	acceptRule(rule)

	preexisting := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testRuleAdvV4}, // no label
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testVIPPrefix},
		},
	}

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
}

// TestNetworkGatewayReconciler_ReturnsOrphanSweepFailure covers the third
// swallowed error from #365. The sweep is crash recovery, so its failure
// must be retried -- and the status write that precedes it still has to
// land, hence the Ready assertion.
func TestNetworkGatewayReconciler_ReturnsOrphanSweepFailure(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA)

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
// namespaced only -- withdrawNodeAdvertisements matches purely on Name, so
// nothing else about the object matters for these tests.
func newAdvertisement(name string) *bgpv1alpha1.BGPAdvertisement {
	return &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
	}
}

// TestNetworkGatewayReconciler_WithdrawsAdvertisementsForDepartedGatewayNode
// is the regression test for #406: gw-b's NetworkGateway is deleted while
// gw-b's own per-rule BGPAdvertisement routes are still around (an
// earlier, Full-NAT-era version of this test also seeded a self-address
// route -- DSR's anycast model has no self-address to advertise at all, so
// that fixture no longer applies here). gw-a's process -- the only one
// left to react, since gw-b's own process is presumably already gone --
// must withdraw every one of them on the NotFound reconcile it receives
// for gw-b's deletion, without touching gw-a's own advertisements for the
// same rule.
func TestNetworkGatewayReconciler_WithdrawsAdvertisementsForDepartedGatewayNode(t *testing.T) {
	scheme := newRuleTestScheme(t)
	gwA := newTestGateway(testNodeGWA) // gw-a's own gateway; still exists

	ruleV4 := newAdvertisement(testRuleName + "-" + testNodeGWB + "-v4")
	ruleV6 := newAdvertisement(testRuleName + "-" + testNodeGWB + "-v6")
	otherRuleV4 := newAdvertisement("other-rule-" + testNodeGWB + "-v4")
	survivorAdv := newAdvertisement(testRuleName + "-" + testNodeGWA + "-v4")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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

	ruleV4 := newAdvertisement(testRuleName + "-" + testNodeGWA + "-v4")

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}).
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
