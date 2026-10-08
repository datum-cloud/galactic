// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.datum.net/galactic/internal/gateway"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// testRuleUID is the UID the drain and owner-reference tests give their rule,
// since the fake client does not assign one.
const testRuleUID = types.UID("rule-1-uid")

// testRuleKeyString is testRuleName's key in the engine's desired state.
const testRuleKeyString = testNamespace + "/" + testRuleName

// advWriteCounter counts BGPAdvertisement creates and updates and NetworkRule
// status writes, the two things a draining rule must never cause.
type advWriteCounter struct {
	advWrites  atomic.Int32
	ruleWrites atomic.Int32
}

func (w *advWriteCounter) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*bgpv1alpha1.BGPAdvertisement); ok {
				w.advWrites.Add(1)
			}
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if _, ok := obj.(*bgpv1alpha1.BGPAdvertisement); ok {
				w.advWrites.Add(1)
			}
			return c.Update(ctx, obj, opts...)
		},
		SubResourceUpdate: func(
			ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption,
		) error {
			if _, ok := obj.(*bgpv1alpha1.NetworkRule); ok {
				w.ruleWrites.Add(1)
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	}
}

func (w *advWriteCounter) reset() {
	w.advWrites.Store(0)
	w.ruleWrites.Store(0)
}

// newFinalizedRule returns testRuleName, accepted, carrying the teardown
// finalizer and testRuleUID, as NetworkRuleReconciler leaves a live rule.
func newFinalizedRule() *bgpv1alpha1.NetworkRule {
	rule := newTestRule(testRuleName, "vpc-1", testVIP)
	acceptRule(rule)
	rule.UID = testRuleUID
	rule.Finalizers = []string{networkRuleFinalizer}
	return rule
}

// fakeClock is a settable clock for NetworkGatewayReconciler.now.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// TestNetworkGatewayReconciler_DrainsDeletedRuleUntilWithdrawn is the
// regression test for #715. A deleting rule used to leave the engine's desired
// state on the same pass that saw its deletion timestamp, so RemoveRule ran
// while its advertisements were still published. It must instead stay loaded,
// unadvertised and with its status untouched, until no labelled advertisement
// remains and ruleDrainDelay has passed, even after the object is gone.
func TestNetworkGatewayReconciler_DrainsDeletedRuleUntilWithdrawn(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newFinalizedRule()

	var writes advWriteCounter
	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
			newBackendAttachment("vpc-1"), rule).
		WithInterceptorFuncs(writes.funcs()).
		Build()

	engine := newFakeGatewayEngine()
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	r.now = clock.now
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	reconcile := func(step string) ctrl.Result {
		t.Helper()
		res, err := r.Reconcile(ctx, req)
		if err != nil {
			t.Fatalf("%s: Reconcile: %v", step, err)
		}
		return res
	}
	assertLoaded := func(step string, want bool) {
		t.Helper()
		if _, ok := engine.lastDesired.Rules[testRuleKeyString]; ok != want {
			t.Fatalf("%s: rule in desired state = %t, want %t", step, ok, want)
		}
	}

	reconcile("live")
	assertLoaded("live", true)
	adv := &bgpv1alpha1.BGPAdvertisement{}
	if err := fakeClient.Get(ctx, testRuleKey(testRuleAdvV4), adv); err != nil {
		t.Fatalf("live: get BGPAdvertisement %s: %v", testRuleAdvV4, err)
	}

	// The finalizer holds the object, so this only sets its deletion
	// timestamp, the state NetworkRuleReconciler.reconcileDelete starts from.
	if err := fakeClient.Delete(ctx, rule); err != nil {
		t.Fatalf("delete NetworkRule: %v", err)
	}

	writes.reset()
	if res := reconcile("draining"); res.RequeueAfter != 0 {
		t.Errorf("draining: RequeueAfter = %s, want 0 while an advertisement remains", res.RequeueAfter)
	}
	assertLoaded("draining", true)
	if got := writes.advWrites.Load(); got != 0 {
		t.Errorf("draining: %d BGPAdvertisement writes, want 0 (a deleting rule is never re-advertised)", got)
	}
	if got := writes.ruleWrites.Load(); got != 0 {
		t.Errorf("draining: %d NetworkRule status writes, want 0 (Programmed is left alone)", got)
	}

	// reconcileDelete withdraws the route.
	if err := fakeClient.Delete(ctx, adv); err != nil {
		t.Fatalf("delete BGPAdvertisement: %v", err)
	}

	res := reconcile("withdrawn")
	assertLoaded("withdrawn", true)
	if res.RequeueAfter != ruleDrainDelay {
		t.Errorf("withdrawn: RequeueAfter = %s, want %s", res.RequeueAfter, ruleDrainDelay)
	}

	// reconcileDelete removes the finalizer and the object goes away.
	current := &bgpv1alpha1.NetworkRule{}
	if err := fakeClient.Get(ctx, testRuleKey(testRuleName), current); err != nil {
		t.Fatalf("get NetworkRule: %v", err)
	}
	current.Finalizers = nil
	if err := fakeClient.Update(ctx, current); err != nil {
		t.Fatalf("remove finalizer: %v", err)
	}
	if err := fakeClient.Get(ctx, testRuleKey(testRuleName), current); !apierrors.IsNotFound(err) {
		t.Fatalf("get NetworkRule after finalizer removal: err = %v, want NotFound", err)
	}

	clock.t = clock.t.Add(2 * time.Second)
	res = reconcile("gone, delay running")
	assertLoaded("gone, delay running", true)
	if want := ruleDrainDelay - 2*time.Second; res.RequeueAfter != want {
		t.Errorf("gone, delay running: RequeueAfter = %s, want %s", res.RequeueAfter, want)
	}

	clock.t = clock.t.Add(ruleDrainDelay)
	res = reconcile("delay over")
	assertLoaded("delay over", false)
	if res.RequeueAfter != 0 {
		t.Errorf("delay over: RequeueAfter = %s, want 0", res.RequeueAfter)
	}
	if err := fakeClient.Get(ctx, testRuleKey(testRuleAdvV4), adv); !apierrors.IsNotFound(err) {
		t.Errorf("BGPAdvertisement %s after drain: err = %v, want NotFound", testRuleAdvV4, err)
	}
}

// TestNetworkGatewayReconciler_DrainingRuleKeepsLastLoadedState covers a
// draining rule that no longer builds, here because its backend's
// advertisement was deleted alongside it. The rule as last loaded stays in
// desired state rather than leaving the datapath before its route is
// withdrawn.
func TestNetworkGatewayReconciler_DrainingRuleKeepsLastLoadedState(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	backendRouter, backendAdv, backendVRF := newBackendFixtures("vpc-1")
	rule := newFinalizedRule()

	fakeClient := newIndexedClientBuilder(scheme).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkRule{}).
		WithObjects(newTestGateway(testNodeGWA), newTestRouter(), backendRouter, backendAdv, backendVRF,
			newBackendAttachment("vpc-1"), rule).
		Build()

	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(fakeClient, scheme, engine, testNodeGWA)
	req := ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("live Reconcile: %v", err)
	}
	loaded, ok := engine.lastDesired.Rules[testRuleKeyString]
	if !ok {
		t.Fatal("live: rule missing from desired state")
	}

	if err := fakeClient.Delete(ctx, rule); err != nil {
		t.Fatalf("delete NetworkRule: %v", err)
	}
	if err := fakeClient.Delete(ctx, backendAdv); err != nil {
		t.Fatalf("delete backend BGPAdvertisement: %v", err)
	}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("draining Reconcile: %v", err)
	}
	got, ok := engine.lastDesired.Rules[testRuleKeyString]
	if !ok {
		t.Fatal("draining: rule that no longer builds left desired state before its route was withdrawn")
	}
	if len(got.Backends) != len(loaded.Backends) || got.Backends[0].USID != loaded.Backends[0].USID {
		t.Errorf("draining: desired rule = %+v, want the last loaded %+v", got, loaded)
	}
}

// TestApplyBGPAdvertisements_SkipsDeletingRule covers a pass working from a
// stale rule list: an advertisement must never be created, or recreated, for
// a rule that is already being deleted.
func TestApplyBGPAdvertisements_SkipsDeletingRule(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	fakeClient := newIndexedClientBuilder(scheme).Build()
	r := newGatewayReconciler(fakeClient, scheme, newFakeGatewayEngine(), testNodeGWA)

	rule := newFinalizedRule()
	now := metav1.Now()
	rule.DeletionTimestamp = &now
	desired := gateway.DesiredRule{
		Key:          testRuleKeyString,
		VIPAddresses: []netip.Addr{netip.MustParseAddr(testVIP)},
	}

	if err := r.applyBGPAdvertisements(ctx, rule, desired, testRouterName); err != nil {
		t.Fatalf("applyBGPAdvertisements: %v", err)
	}
	advList := &bgpv1alpha1.BGPAdvertisementList{}
	if err := fakeClient.List(ctx, advList); err != nil {
		t.Fatalf("list BGPAdvertisements: %v", err)
	}
	if len(advList.Items) != 0 {
		t.Errorf("got %d BGPAdvertisements for a deleting rule, want 0", len(advList.Items))
	}
}

// assertRuleOwnerReference fails the test unless adv carries a non-controller
// owner reference to testRuleName with blockOwnerDeletion unset, the shape
// that lets garbage collection delete it without extra RBAC.
func assertRuleOwnerReference(t *testing.T, adv *bgpv1alpha1.BGPAdvertisement) {
	t.Helper()
	for _, ref := range adv.OwnerReferences {
		if ref.Kind != "NetworkRule" || ref.Name != testRuleName {
			continue
		}
		if ref.UID != testRuleUID {
			t.Errorf("owner reference UID = %q, want %q", ref.UID, testRuleUID)
		}
		if ref.APIVersion != bgpv1alpha1.GroupVersion.String() {
			t.Errorf("owner reference APIVersion = %q, want %q", ref.APIVersion, bgpv1alpha1.GroupVersion.String())
		}
		if ref.Controller != nil && *ref.Controller {
			t.Error("owner reference is a controller reference, want a plain one")
		}
		if ref.BlockOwnerDeletion != nil {
			t.Errorf("owner reference blockOwnerDeletion = %t, want unset", *ref.BlockOwnerDeletion)
		}
		return
	}
	t.Errorf("BGPAdvertisement %s has no owner reference to NetworkRule %s; got %+v",
		adv.Name, testRuleName, adv.OwnerReferences)
}

// TestRuleDrainTracker_RecreatedRuleDropsHold covers a rule recreated under
// the same name while its predecessor's drain hold is running: it is served as
// the new rule, and a later deletion starts a fresh hold.
func TestRuleDrainTracker_RecreatedRuleDropsHold(t *testing.T) {
	var tr ruleDrainTracker
	t0 := time.Unix(1_000_000, 0)
	rule := gateway.DesiredRule{Key: testRuleKeyString}

	tr.settle(t0, testNamespace, map[string]gateway.DesiredRule{rule.Key: rule}, map[string]bool{rule.Key: true})

	desired := map[string]gateway.DesiredRule{}
	if got := tr.settle(t0, testNamespace, desired, map[string]bool{}); got != ruleDrainDelay {
		t.Fatalf("deleted: requeue = %s, want %s", got, ruleDrainDelay)
	}
	if _, ok := desired[rule.Key]; !ok {
		t.Fatal("deleted: rule not held")
	}

	tr.settle(t0.Add(time.Second), testNamespace,
		map[string]gateway.DesiredRule{rule.Key: rule}, map[string]bool{rule.Key: true})
	if _, held := tr.holdUntil[rule.Key]; held {
		t.Fatal("recreated: hold survived the rule coming back")
	}

	desired = map[string]gateway.DesiredRule{}
	if got := tr.settle(t0.Add(2*time.Second), testNamespace, desired, map[string]bool{}); got != ruleDrainDelay {
		t.Errorf("deleted again: requeue = %s, want a fresh %s", got, ruleDrainDelay)
	}
}

// TestRuleDrainTracker_OtherNamespaceUntouched covers a pass in one namespace
// leaving another namespace's remembered rules alone.
func TestRuleDrainTracker_OtherNamespaceUntouched(t *testing.T) {
	var tr ruleDrainTracker
	t0 := time.Unix(1_000_000, 0)
	other := gateway.DesiredRule{Key: "other/rule"}

	tr.settle(t0, "other", map[string]gateway.DesiredRule{other.Key: other}, map[string]bool{other.Key: true})
	desired := map[string]gateway.DesiredRule{}
	if got := tr.settle(t0, testNamespace, desired, map[string]bool{}); got != 0 {
		t.Errorf("requeue = %s, want 0", got)
	}
	if len(desired) != 0 {
		t.Errorf("desired = %+v, want empty", desired)
	}
	if _, ok := tr.lastLoaded(other.Key); !ok {
		t.Error("other namespace's rule forgotten")
	}
}
