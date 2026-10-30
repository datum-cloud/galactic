// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	api "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/gateway"
)

const testSharedControl = "control"
const testSharedMedia = "media"
const testSharedNodeA = "shared-node-a"
const testSharedNodeB = "shared-node-b"

func sharedAddressFixture() (*api.NetworkServiceAddress, *api.NetworkService) {
	group := api.NetworkServiceAddressGroup{
		UID:        "allocation-1",
		Generation: 1,
		Revision:   "inventory-1",
		Listeners: []api.NetworkServiceAddressListener{
			{Name: testSharedControl, Protocol: api.NetworkServiceProtocolTCP, Port: 443},
			{
				Name:      testSharedMedia,
				Protocol:  api.NetworkServiceProtocolUDP,
				PortRange: &api.PortRange{Start: 20000, End: 20999},
			},
		},
	}
	address := &api.NetworkServiceAddress{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "address-1",
			Namespace:  testNamespace,
			UID:        types.UID("anchor-1"),
			Generation: 1,
		},
		Spec: api.NetworkServiceAddressSpec{VIPAddress: "2001:db8::1", VPCRef: "vpc-1", Group: group},
	}
	rule := &api.NetworkService{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testSharedControl,
			Namespace:  testNamespace,
			UID:        types.UID("rule-1"),
			Generation: 1,
		},
		Spec: api.NetworkServiceSpec{
			VPCRef:       "vpc-1",
			VIPAddresses: []string{"2001:db8::1"},
			Protocol:     api.NetworkServiceProtocolTCP,
			Port:         443,
			BackendPort:  8443,
			AddressGroup: group.DeepCopy(),
		},
	}
	rule.Spec.AddressGroup.ListenerName = testSharedControl
	return address, rule
}

func TestAddressInventoryAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*api.NetworkServiceAddress, *api.NetworkService)
		valid  bool
	}{
		{"CurrentInventory", func(*api.NetworkServiceAddress, *api.NetworkService) {}, true},
		{"ExpandedIPv6", func(_ *api.NetworkServiceAddress, r *api.NetworkService) {
			r.Spec.VIPAddresses = []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}
		}, true},
		{"LegacyCannotBypassExpandedVIP", func(_ *api.NetworkServiceAddress, r *api.NetworkService) {
			r.Spec.VIPAddresses = []string{"2001:0db8:0:0:0:0:0:1"}
			r.Spec.AddressGroup = nil
		}, false},
		{"StaleRevision", func(_ *api.NetworkServiceAddress, r *api.NetworkService) {
			r.Spec.AddressGroup.Revision = testConflictOld
		}, false},
		{"ReplacedAllocation", func(a *api.NetworkServiceAddress, _ *api.NetworkService) {
			a.Spec.Group.UID = "replacement"
		}, false},
		{"UndeclaredSocket", func(_ *api.NetworkServiceAddress, r *api.NetworkService) { r.Spec.Port = 444 }, false},
		{"WrongVPC", func(_ *api.NetworkServiceAddress, r *api.NetworkService) { r.Spec.VPCRef = "different-vpc" }, false},
		{"IntersectingInventory", func(a *api.NetworkServiceAddress, _ *api.NetworkService) {
			overlap := api.NetworkServiceAddressListener{Name: "overlap", Protocol: api.NetworkServiceProtocolUDP, Port: 20500}
			a.Spec.Group.Listeners = append(a.Spec.Group.Listeners, overlap)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r := sharedAddressFixture()
			tc.mutate(a, r)
			err := addressRuleError(r, addressInventory{a.Spec.VIPAddress: a})
			if (err == nil) != tc.valid {
				t.Fatalf("error=%v, want valid=%t", err, tc.valid)
			}
		})
	}
}

type ownedTestEngine struct {
	*fakeGatewayEngine
	owned []netip.Addr
}

func (e *ownedTestEngine) SetBlockedVIPs(context.Context, []netip.Addr) error { return nil }
func (e *ownedTestEngine) RenewVIPs(context.Context, []netip.Addr) error      { return nil }
func (e *ownedTestEngine) SetOwnedVIPs(_ context.Context, owned []netip.Addr) error {
	e.owned = owned
	return nil
}

func TestDuplicateAddressInventoriesWithdrawAllAdvertisements(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	a, r := sharedAddressFixture()
	b := a.DeepCopy()
	b.Name = "address-2"
	b.UID = "anchor-2"
	objects := make([]client.Object, 0, 4)
	objects = append(objects, a, b)
	for _, address := range []*api.NetworkServiceAddress{a, b} {
		objects = append(
			objects,
			&api.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Name:      addressAdvertisementName(address.Name, testNodeGWA),
					Namespace: testNamespace,
					Labels: map[string]string{
						serviceAddressLabel: address.Name,
						gatewayNodeLabel:    gatewayNodeLabelValue(testNodeGWA),
					},
				},
			},
		)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&api.NetworkServiceAddress{}).
		WithObjects(objects...).
		Build()
	engine := &ownedTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
	reconciler := newGatewayReconciler(c, scheme, engine, testNodeGWA)
	inventory, err := reconciler.prepareAddressInventory(ctx, testNamespace, []api.NetworkService{*r})
	if err != nil {
		t.Fatal(err)
	}
	if inventory[a.Spec.VIPAddress] != nil || len(engine.owned) == 0 {
		t.Fatal("collision must retain owned guard and deny ownership")
	}
	status := gateway.EngineStatus{Healthy: true}
	_, err = reconciler.publishAddressOutcomes(ctx, testNamespace, inventory, nil, status, testRouterName)
	if err != nil {
		t.Fatal(err)
	}
	ads := &api.BGPAdvertisementList{}
	if err := c.List(ctx, ads); err != nil {
		t.Fatal(err)
	}
	if len(ads.Items) != 0 {
		t.Fatalf("collision retained %d advertisements", len(ads.Items))
	}
}

func TestAddressAdvertisementWaitsForLegacyWithdrawal(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	a, _ := sharedAddressFixture()
	old := &api.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "shared-legacy-advertisement",
			Namespace:  testNamespace,
			Finalizers: []string{"routing-withdrawal"},
			Labels: map[string]string{
				networkRuleLabel: testSharedControl,
				gatewayNodeLabel: gatewayNodeLabelValue(testNodeGWA),
			},
		},
		Spec: api.BGPAdvertisementSpec{Prefixes: []api.Prefix{"2001:db8::1/128"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(a, old).Build()
	r := newGatewayReconciler(c, scheme, newFakeGatewayEngine(), testNodeGWA)
	if installed, err := r.reconcileAddressAdvertisement(ctx, a, testRouterName, true); err != nil || installed {
		t.Fatalf("installed=%t err=%v", installed, err)
	}
	key := types.NamespacedName{Namespace: testNamespace, Name: addressAdvertisementName(a.Name, testNodeGWA)}
	if err := c.Get(ctx, key, &api.BGPAdvertisement{}); !apierrors.IsNotFound(err) {
		t.Fatalf("new announcement created before old withdrew: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(old), old); err != nil {
		t.Fatal(err)
	}
	old.Finalizers = nil
	if err := c.Update(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileAddressAdvertisement(ctx, a, testRouterName, true); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, key, &api.BGPAdvertisement{}); err != nil {
		t.Fatalf("new address announcement missing: %v", err)
	}
}

func TestGroupedWithdrawalRequiresAllNodesAndCurrentGeneration(t *testing.T) {
	_, r := sharedAddressFixture()
	old := metav1.NewTime(time.Now().Add(-time.Minute))
	for _, node := range []string{testSharedNodeA, testSharedNodeB} {
		for _, kind := range []string{programmedConditionType(node), advertisedConditionType(node)} {
			r.Status.Conditions = append(
				r.Status.Conditions,
				metav1.Condition{
					Type:               kind,
					Status:             metav1.ConditionFalse,
					Reason:             reasonAddressWithdrawn,
					ObservedGeneration: r.Generation,
					LastTransitionTime: old,
				},
			)
		}
	}
	if !groupedRuleWithdrawn(r, []string{testSharedNodeA}) {
		t.Fatal("complete withdrawal must include historical node")
	}
	meta.FindStatusCondition(r.Status.Conditions, programmedConditionType(testSharedNodeB)).ObservedGeneration = 0
	if groupedRuleWithdrawn(r, []string{testSharedNodeA}) {
		t.Fatal("stale historical-node acknowledgment must block cleanup")
	}
}

func TestIntervalOwnershipCrossesRangeAndSingleton(t *testing.T) {
	_, a := sharedAddressFixture()
	a.Spec.Protocol = api.NetworkServiceProtocolUDP
	a.Spec.Port = 0
	a.Spec.PortRange = &api.PortRange{Start: 20000, End: 20999}
	a.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
	b := a.DeepCopy()
	b.Name = "second"
	b.Spec.PortRange = nil
	b.Spec.Port = 20500
	b.CreationTimestamp = metav1.Now()
	lost := tenantVIPConflicts([]api.NetworkService{*a, *b}, testNamespace)
	if lost[client.ObjectKeyFromObject(b)] != client.ObjectKeyFromObject(a) {
		t.Fatal("singleton inside older range must lose")
	}
	b.Spec.Port = 21000
	if len(tenantVIPConflicts([]api.NetworkService{*a, *b}, testNamespace)) != 0 {
		t.Fatal("adjacent singleton must be independent")
	}
}

func TestSharedAddressHealthySiblingAndActivationReceipt(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	a, healthy := sharedAddressFixture()
	unhealthy := healthy.DeepCopy()
	unhealthy.Name = testSharedMedia
	unhealthy.Spec.AddressGroup.ListenerName = testSharedMedia
	unhealthy.Spec.Port = 0
	unhealthy.Spec.Protocol = api.NetworkServiceProtocolUDP
	unhealthy.Spec.PortRange = &api.PortRange{Start: 20000, End: 20999}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&api.NetworkService{}, &api.NetworkServiceAddress{}).
		WithObjects(a, healthy, unhealthy).
		Build()
	r := newGatewayReconciler(c, scheme, newFakeGatewayEngine(), testNodeGWA)
	key := healthy.Namespace + "/" + healthy.Name
	dr := gateway.DesiredRule{Key: key, Backends: []gateway.DesiredBackend{{}}}
	outcomes := []ruleOutcome{
		{rule: healthy, desired: dr},
		{rule: unhealthy, buildErr: errors.New("no healthy backends")},
	}
	desired := gateway.EngineState{Rules: map[string]gateway.DesiredRule{key: dr}}
	inventory := addressInventory{a.Spec.VIPAddress: a}
	if err := r.primeGroupedServing(ctx, inventory, desired, outcomes); err != nil {
		t.Fatal(err)
	}
	current := &api.NetworkService{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(healthy), current); err != nil {
		t.Fatal(err)
	}
	if cond := meta.FindStatusCondition(current.Status.Conditions, programmedConditionType(testNodeGWA)); cond == nil ||
		cond.Status != metav1.ConditionUnknown {
		t.Fatalf("activation didn't persist invalidated cleanup acknowledgment: %+v", cond)
	}
	status := gateway.EngineStatus{Healthy: true, Rules: []gateway.RuleStatus{{Key: key, Applied: true}}}
	if _, err := r.publishAddressOutcomes(ctx, testNamespace, inventory, outcomes, status, testRouterName); err != nil {
		t.Fatal(err)
	}
	ad := &api.BGPAdvertisement{}
	adKey := types.NamespacedName{Namespace: testNamespace, Name: addressAdvertisementName(a.Name, testNodeGWA)}
	if err := c.Get(ctx, adKey, ad); err != nil {
		t.Fatal("healthy listener failed to advertise shared address", err)
	}
	status.Healthy = false
	if _, err := r.publishAddressOutcomes(ctx, testNamespace, inventory, outcomes, status, testRouterName); err != nil {
		t.Fatal(err)
	}
	currentAddress := &api.NetworkServiceAddress{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(a), currentAddress); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(currentAddress.Status.Conditions, programmedConditionType(testNodeGWA))
	if cond == nil ||
		cond.Status != metav1.ConditionUnknown {
		t.Fatalf("unconfirmed cleanup acknowledged as withdrawn: %+v", cond)
	}
}

func TestAddressRetirementConflictsWithConcurrentActivation(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	a, _ := sharedAddressFixture()
	a.Finalizers = []string{serviceAddressFinalizer}
	now := metav1.Now()
	a.DeletionTimestamp = &now
	for _, kind := range []string{programmedConditionType(testNodeGWA), advertisedConditionType(testNodeGWA)} {
		a.Status.Conditions = append(
			a.Status.Conditions,
			metav1.Condition{
				Type:               kind,
				Status:             metav1.ConditionFalse,
				Reason:             reasonAddressWithdrawn,
				ObservedGeneration: a.Generation,
				LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Minute)),
			},
		)
	}
	var raced bool
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&api.NetworkServiceAddress{}).
		WithObjects(a, newTestGateway(testNodeGWA)).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object,
				patch client.Patch, opts ...client.PatchOption) error {
				if address, ok := obj.(*api.NetworkServiceAddress); ok && !raced && len(address.Finalizers) == 0 {
					raced = true
					newer := &api.NetworkServiceAddress{}
					if err := c.Get(ctx, client.ObjectKeyFromObject(address), newer); err != nil {
						return err
					}
					condition := meta.FindStatusCondition(newer.Status.Conditions, programmedConditionType(testNodeGWA))
					condition.Status = metav1.ConditionUnknown
					if err := c.Status().Update(ctx, newer); err != nil {
						return err
					}
				}
				return c.Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()
	r := newGatewayReconciler(c, scheme, newFakeGatewayEngine(), testNodeGWA)
	if err := r.finalizeAddress(ctx, a); !apierrors.IsConflict(err) {
		t.Fatalf("expected retirement/activation CAS conflict, got %v", err)
	}
	current := &api.NetworkServiceAddress{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(a), current); err != nil {
		t.Fatal(err)
	}
	if len(current.Finalizers) == 0 {
		t.Fatal("concurrent activation lost allocation guard")
	}
	if err := r.finalizeAddress(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(a), current); err != nil {
		t.Fatal("Unknown acknowledgment did not retain address", err)
	}
}

func TestSharedAddressRequiresFreshRouterLeaseCapability(t *testing.T) {
	for _, tc := range []struct {
		name     string
		support  bool
		observed int64
		age      time.Duration
		allowed  bool
	}{
		{"LegacyRouter", false, 1, 0, false},
		{"FreshRouter", true, 1, 0, true},
		{"OldGeneration", true, 0, 0, false},
		{"StalledRouter", true, 1, 2 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newRuleTestScheme(t)
			router := newTestRouter()
			router.Generation = 1
			router.Status.SupportsAdvertisementLeases = tc.support
			router.Status.ObservedGeneration = tc.observed
			when := metav1.NewTime(time.Now().Add(-tc.age))
			router.Status.LastSuccessfulReconcileTime = &when
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()
			r := newGatewayReconciler(c, scheme, newFakeGatewayEngine(), testNodeGWA)
			allowed, err := r.routerLeaseSupport(context.Background(), testNamespace, router.Name)
			if err != nil || allowed != tc.allowed {
				t.Fatalf("allowed=%t error=%v, want %t", allowed, err, tc.allowed)
			}
		})
	}
}

type renewalTestEngine struct {
	*fakeGatewayEngine
	renewals int
}

func (e *renewalTestEngine) SetBlockedVIPs(context.Context, []netip.Addr) error { return nil }
func (e *renewalTestEngine) SetOwnedVIPs(context.Context, []netip.Addr) error   { return nil }
func (e *renewalTestEngine) RenewVIPs(_ context.Context, addresses []netip.Addr) error {
	e.renewals += len(addresses)
	return nil
}

func TestSharedServingLeaseRenewalRequiresConfirmedCleanup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		healthy  bool
		sweepErr error
		renew    bool
	}{
		{"Converged", true, nil, true},
		{"PartialApply", false, nil, false},
		{"OrphanFailure", true, errors.New("sweep failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newRuleTestScheme(t)
			gw := newTestGateway(testNodeGWA)
			address, _ := sharedAddressFixture()
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&api.NetworkGateway{}).
				WithObjects(gw, address).
				Build()
			engine := &renewalTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
			engine.orphansErr = tc.sweepErr
			r := newGatewayReconciler(c, scheme, engine, testNodeGWA)
			r.ownedAddresses = []netip.Addr{netip.MustParseAddr(address.Spec.VIPAddress)}
			r.desiredOwnedAddresses = r.ownedAddresses
			err := r.finishAddressConvergence(
				context.Background(),
				gw,
				gateway.EngineState{},
				&gateway.EngineStatus{Healthy: tc.healthy},
				0,
				addressInventory{address.Spec.VIPAddress: address},
			)
			if (err != nil) != (tc.sweepErr != nil) {
				t.Fatalf("error=%v", err)
			}
			if (engine.renewals > 0) != tc.renew {
				t.Fatalf("renewals=%d, want renewal=%t", engine.renewals, tc.renew)
			}
		})
	}
}

func TestSharedAdvertisementLeaseRenewalPreservesReadiness(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	a, _ := sharedAddressFixture()
	deadline := metav1.NewTime(time.Now().Add(10 * time.Second))
	ad := &api.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:       addressAdvertisementName(a.Name, testNodeGWA),
			Namespace:  testNamespace,
			Generation: 1,
		},
		Spec: api.BGPAdvertisementSpec{
			ExpiresAt:     &deadline,
			RouterRef:     api.RouterRef{Name: testRouterName},
			AddressFamily: api.AddressFamily{AFI: api.AFIL2VPN, SAFI: api.SAFIEVPN},
			Prefixes:      []api.Prefix{api.Prefix(a.Spec.VIPAddress + "/128")},
		},
		Status: api.BGPAdvertisementStatus{
			Conditions: []metav1.Condition{
				{Type: ConditionAdvertised, Status: metav1.ConditionTrue, ObservedGeneration: 1},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&api.BGPAdvertisement{}).WithObjects(a, ad).
		WithInterceptorFuncs(interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch,
			obj client.Object, opts ...client.UpdateOption) error {
			if advertisement, ok := obj.(*api.BGPAdvertisement); ok {
				advertisement.Generation++
			}
			return c.Update(ctx, obj, opts...)
		}}).
		Build()
	r := newGatewayReconciler(c, scheme, newFakeGatewayEngine(), testNodeGWA)
	installed, err := r.reconcileAddressAdvertisement(ctx, a, testRouterName, true)
	if err != nil || !installed {
		t.Fatalf("lease-only renewal lost existing installed path: installed=%t error=%v", installed, err)
	}
	current := &api.BGPAdvertisement{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ad), current); err != nil {
		t.Fatal(err)
	}
	if current.Generation != 2 || !current.Spec.ExpiresAt.After(deadline.Time) {
		t.Fatal("fixture did not exercise renewed generation")
	}
	if installed, err := r.reconcileAddressAdvertisement(ctx, a, "replacement-router", true); err != nil || installed {
		t.Fatalf("changed path reused old readiness: installed=%t error=%v", installed, err)
	}
}

func TestRetiredGatewayAcknowledgesAddressWithdrawal(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	a, _ := sharedAddressFixture()
	a.Finalizers = []string{serviceAddressFinalizer}
	now := metav1.Now()
	a.DeletionTimestamp = &now
	for _, node := range []string{testNodeGWA, testSharedNodeB} {
		for _, kind := range []string{programmedConditionType(node), advertisedConditionType(node)} {
			state := metav1.ConditionFalse
			if node == testSharedNodeB {
				state = metav1.ConditionTrue
			}
			a.Status.Conditions = append(
				a.Status.Conditions,
				metav1.Condition{
					Type:               kind,
					Status:             state,
					Reason:             "BeforeRemoval",
					ObservedGeneration: a.Generation,
					LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Hour)),
				},
			)
		}
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&api.NetworkServiceAddress{}).
		WithObjects(a, newTestGateway(testNodeGWA)).
		Build()
	r := newGatewayReconciler(c, scheme, newFakeGatewayEngine(), testNodeGWA)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testSharedNodeB}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	stoppedEngine := newFakeGatewayEngine()
	departing := newGatewayReconciler(c, scheme, stoppedEngine, testSharedNodeB)
	if _, err := departing.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if !stoppedEngine.stopped {
		t.Fatal("fixture did not confirm successful engine stop")
	}
	t.Log("departed gateway successfully stopped its engine")
	if err := r.finalizeAddress(ctx, a); err != nil {
		t.Fatal(err)
	}
	current := &api.NetworkServiceAddress{}
	err := c.Get(ctx, client.ObjectKeyFromObject(a), current)
	if err == nil {
		t.Fatalf(
			"address permanently retained departed node conditions despite no services or advertisements: %+v",
			current.Status.Conditions,
		)
	}
	if !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
}
func TestNewInventoryCannotBorrowOldProgramming(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	a, rule := sharedAddressFixture()
	previous := a.DeepCopy()
	a.Generation++
	a.Spec.Group.Generation++
	a.Spec.Group.Revision = "inventory-2"
	a.Spec.Group.Listeners[0].Port = 444
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&api.NetworkServiceAddress{}).
		WithObjects(a).
		Build()
	r := newGatewayReconciler(c, scheme, newFakeGatewayEngine(), testNodeGWA)
	key := rule.Namespace + "/" + rule.Name
	outcome := ruleOutcome{rule: rule, desired: gateway.DesiredRule{Key: key, Backends: []gateway.DesiredBackend{{}}}}
	_, err := r.publishAddressOutcomes(
		ctx,
		testNamespace,
		addressInventory{a.Spec.VIPAddress: previous},
		[]ruleOutcome{outcome},
		gateway.EngineStatus{Healthy: true, Rules: []gateway.RuleStatus{{Key: key, Applied: true}}},
		testRouterName,
	)
	if err != nil {
		return
	}
	current := &api.NetworkServiceAddress{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(a), current); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(current.Status.Conditions, programmedConditionType(testNodeGWA))
	if cond != nil && cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == a.Generation {
		t.Fatalf("new inventory borrowed old programming receipt: %+v", cond)
	}
}

func TestTenantAddressAuthorityAdvertisementAndRetirement(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	address, rule := sharedAddressFixture()
	address.Name = "nlb-address-" + strings.Repeat("a", 64)
	address.Namespace = "project-a"
	rule.Namespace = address.Namespace
	vpc := newTenantVPC(address.Spec.VPCRef)
	vpc.Namespace = address.Namespace
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&api.NetworkService{}, &api.NetworkServiceAddress{}).
		WithObjects(address, rule, vpc, newTestGateway(testNodeGWA)).
		Build()
	engine := &ownedTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
	r := newGatewayReconciler(c, scheme, engine, testNodeGWA)
	r.Scope = sharedAddressProjectScope()
	inventory, err := r.prepareAddressInventory(ctx, testNamespace, []api.NetworkService{*rule})
	if err != nil {
		t.Fatal(err)
	}
	if err := addressRuleError(rule, inventory); err != nil {
		t.Fatalf("tenant authority rejected: %v", err)
	}
	key := rule.Namespace + "/" + rule.Name
	dr := gateway.DesiredRule{Key: key, Backends: []gateway.DesiredBackend{{}}}
	outcomes := []ruleOutcome{{rule: rule, desired: dr}}
	desired := gateway.EngineState{Rules: map[string]gateway.DesiredRule{key: dr}}
	if err := r.primeGroupedServing(ctx, inventory, desired, outcomes); err != nil {
		t.Fatal(err)
	}
	status := gateway.EngineStatus{Healthy: true, Rules: []gateway.RuleStatus{{Key: key, Applied: true}}}
	if _, err := r.publishAddressOutcomes(ctx, testNamespace, inventory, outcomes, status, testRouterName); err != nil {
		t.Fatal(err)
	}
	ads := &api.BGPAdvertisementList{}
	if err := c.List(ctx, ads); err != nil {
		t.Fatal(err)
	}
	if len(ads.Items) != 1 {
		t.Fatalf("advertisements: %d", len(ads.Items))
	}
	ad := ads.Items[0]
	for _, value := range ad.Labels {
		if errs := validation.IsValidLabelValue(value); len(errs) > 0 {
			t.Fatalf("invalid advertisement label: %v", errs)
		}
	}
	if ad.Namespace != testNamespace || addressKeyFromAdvertisement(&ad) != client.ObjectKeyFromObject(address) ||
		len(ad.OwnerReferences) != 0 ||
		!isNodeAdvertisement(&ad, testNodeGWA) {
		t.Fatalf("wrong tenant advertisement identity: %+v", ad)
	}
	binding := newTestServiceVIPBinding(api.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.SourceRef = &api.ServiceVIPBindingSourceReference{
		Namespace:     rule.Namespace,
		Name:          rule.Name,
		UID:           rule.UID,
		Generation:    rule.Generation,
		AllocationUID: rule.Spec.AddressGroup.UID,
	}
	binder := &ServiceVIPBindingReconciler{Client: c, APIReader: c}
	if allowed, err := binder.bindingSourceAllowed(ctx, binding); err != nil || !allowed {
		t.Fatalf("tenant binding source rejected: %t %v", allowed, err)
	}
	if err := c.Delete(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	address.Spec.Retired = true
	address.Generation++
	if err := c.Update(ctx, address); err != nil {
		t.Fatal(err)
	}
	inventory, err = r.prepareAddressInventory(ctx, testNamespace, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyStatus := gateway.EngineStatus{Healthy: true}
	if _, err := r.publishAddressOutcomes(ctx, testNamespace, inventory, nil, emptyStatus, testRouterName); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if !addressRetirementAcknowledged(address) {
		t.Fatalf("tenant retirement not acknowledged: %+v", address.Status)
	}
	assertRetiredAddressReuse(t, ctx, c, r, engine, address, rule)
}

func TestLateBindingCannotActivateRetiredSource(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	address, rule := sharedAddressFixture()
	address.Spec.Retired = true
	binding := newTestServiceVIPBinding(api.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.SourceRef = &api.ServiceVIPBindingSourceReference{
		Namespace:     rule.Namespace,
		Name:          rule.Name,
		UID:           rule.UID,
		Generation:    rule.Generation,
		AllocationUID: rule.Spec.AddressGroup.UID,
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&api.ServiceVIPBinding{}).
		WithObjects(address, rule, binding).
		Build()
	table := &fakeVIPTable{}
	r := &ServiceVIPBindingReconciler{
		Client:              c,
		APIReader:           c,
		Scheme:              scheme,
		NodeName:            testComputeNodeName,
		VIPTranslationTable: table,
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(binding)}); err != nil {
		t.Fatal(err)
	}
	current := &api.ServiceVIPBinding{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(binding), current); err != nil {
		t.Fatal(err)
	}
	if current.DeletionTimestamp.IsZero() {
		t.Fatal("late binding was not retired")
	}
	if len(table.ingressCalls) != 0 || len(table.egressCalls) != 0 {
		t.Fatal("late binding wrote translation maps")
	}
}

func TestRetirementWaitsForInflightBindingCleanup(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	address, _ := sharedAddressFixture()
	address.Spec.Retired = true
	stoppedGatewayConditions(&address.Status.Conditions, testNodeGWA, address.Generation)
	binding := newTestServiceVIPBinding(api.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Finalizers = []string{serviceVIPBindingFinalizer}
	binding.Spec.SourceRef = &api.ServiceVIPBindingSourceReference{
		Namespace:     address.Namespace,
		Name:          "old-service",
		UID:           "source",
		AllocationUID: address.Spec.Group.UID,
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&api.NetworkServiceAddress{}).
		WithObjects(address, binding).
		Build()
	r := newGatewayReconciler(c, scheme, newFakeGatewayEngine(), testNodeGWA)
	if err := r.finalizeAddress(ctx, address); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if addressRetirementAcknowledged(address) {
		t.Fatal("in-flight binding cleanup was bypassed")
	}
	if err := c.Delete(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := r.finalizeAddress(ctx, address); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if addressRetirementAcknowledged(address) {
		t.Fatal("binding finalizer was bypassed")
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(binding), binding); err != nil {
		t.Fatal(err)
	}
	binding.Finalizers = nil
	if err := c.Update(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := r.finalizeAddress(ctx, address); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if !addressRetirementAcknowledged(address) {
		t.Fatal("confirmed binding cleanup did not release retirement")
	}
}

func assertRetiredAddressReuse(
	t *testing.T,
	ctx context.Context,
	c client.Client,
	r *NetworkGatewayReconciler,
	engine *ownedTestEngine,
	address *api.NetworkServiceAddress,
	rule *api.NetworkService,
) {
	t.Helper()
	var inventory addressInventory
	var err error
	replacement := address.DeepCopy()
	replacement.Name = "replacement"
	replacement.UID = "new-anchor"
	replacement.ResourceVersion = ""
	replacement.Generation = 1
	replacement.Spec.Retired = false
	replacement.Spec.Group.UID = "new-allocation"
	replacement.Status = api.NetworkServiceAddressStatus{}
	if err := c.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	inventory, err = r.prepareAddressInventory(ctx, testNamespace, []api.NetworkService{*rule})
	if err != nil {
		t.Fatal(err)
	}
	if inventory[address.Spec.VIPAddress] == nil ||
		inventory[address.Spec.VIPAddress].Spec.Group.UID != "new-allocation" {
		t.Fatal("retired old UID poisoned new allocation")
	}
	if err := addressRuleError(rule, inventory); err == nil {
		t.Fatal("late old service reopened retired allocation")
	}
	if err := c.Delete(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(replacement), replacement); err != nil {
		t.Fatal(err)
	}
	replacement.Finalizers = nil
	if err := c.Update(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	inventory, err = r.prepareAddressInventory(ctx, testNamespace, []api.NetworkService{*rule})
	if err != nil {
		t.Fatal(err)
	}
	status := gateway.EngineStatus{Healthy: true}
	err = r.finishAddressConvergence(ctx, newTestGateway(testNodeGWA), gateway.EngineState{}, &status, 0, inventory)
	if err != nil {
		t.Fatal(err)
	}
	legacy := rule.DeepCopy()
	legacy.Spec.AddressGroup = nil
	if err := addressRuleError(legacy, inventory); err != nil || len(engine.owned) != 0 {
		t.Fatalf("retired old UID blocked legacy reuse: %v owned=%v", err, engine.owned)
	}
}

func TestStoppedGatewayWaitsForAdvertisementFinalizer(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	address, _ := sharedAddressFixture()
	ad := &api.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace,
		Name: addressAdvertisementName(address.Name, testSharedNodeB), Finalizers: []string{"routing-withdrawal"},
		Labels: map[string]string{
			serviceAddressLabel: address.Name,
			gatewayNodeLabel:    gatewayNodeLabelValue(testSharedNodeB),
		}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(address).WithObjects(address, ad).Build()
	engine := newFakeGatewayEngine()
	r := newGatewayReconciler(c, scheme, engine, testSharedNodeB)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testSharedNodeB}}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.stopped || result.RequeueAfter == 0 {
		t.Fatal("gateway must stop and retry pending BGP cleanup")
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if meta.IsStatusConditionTrue(address.Status.Conditions, stoppedGatewayConditionType(testSharedNodeB)) {
		t.Fatal("BGP cleanup finalizer was bypassed")
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ad), ad); err != nil {
		t.Fatal(err)
	}
	ad.Finalizers = nil
	if err := c.Update(ctx, ad); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(address.Status.Conditions, stoppedGatewayConditionType(testSharedNodeB)) {
		t.Fatal("successful stop was not recorded")
	}
	address.Generation++
	address.Spec.Retired = true
	if err := c.Update(ctx, address); err != nil {
		t.Fatal(err)
	}
	if err := r.finalizeAddress(ctx, address); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if !addressRetirementAcknowledged(address) {
		t.Fatal("later retirement lost departed-node stop receipt")
	}
}

func TestStoppedGatewayWaitsForPersistedOrphanCleanup(t *testing.T) {
	ctx := context.Background()
	scheme := newRuleTestScheme(t)
	address, _ := sharedAddressFixture()
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(address).WithObjects(address).Build()
	datapath := &stoppedGatewayDatapath{persistedRows: 1, sweepErr: errors.New("persisted orphan cleanup failed")}
	// Restart with an empty engine over rows retained from a previous process.
	engine := gateway.NewEngine(datapath, gateway.NoopQuotaEnforcer{}, gateway.NoopTelemetryEmitter{})
	if err := engine.Stop(ctx); err != nil || datapath.persistedRows != 1 {
		t.Fatal("fixture must retain persisted state after an empty-engine Stop")
	}
	r := newGatewayReconciler(c, scheme, engine, testSharedNodeB)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testSharedNodeB}}
	if _, err := r.Reconcile(ctx, req); !errors.Is(err, datapath.sweepErr) {
		t.Fatalf("expected orphan cleanup error, got %v", err)
	}
	if datapath.persistedRows != 1 || datapath.cutoff != 123 {
		t.Fatal("stopped engine must sweep persisted orphan rows using the pre-read cutoff")
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if meta.IsStatusConditionTrue(address.Status.Conditions, stoppedGatewayConditionType(testSharedNodeB)) {
		t.Fatal("failed persisted cleanup must not acknowledge gateway stop")
	}
	datapath.sweepErr = nil
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if datapath.persistedRows != 0 ||
		!meta.IsStatusConditionTrue(address.Status.Conditions, stoppedGatewayConditionType(testSharedNodeB)) {
		t.Fatal("successful persisted cleanup must clear rows before acknowledging gateway stop")
	}
}

// stoppedGatewayDatapath preserves rows independently of the engine's lifetime.
type stoppedGatewayDatapath struct {
	gateway.NoopDatapath
	persistedRows int
	cutoff        uint64
	sweepErr      error
}

func (*stoppedGatewayDatapath) Generation() uint64 { return 123 }

func (d *stoppedGatewayDatapath) ReconcileOrphans(_ context.Context, live []gateway.DesiredRule, cutoff uint64) error {
	d.cutoff = cutoff
	if len(live) != 0 {
		return errors.New("stopped gateway must sweep with an empty live set")
	}
	if d.sweepErr != nil {
		return d.sweepErr
	}
	d.persistedRows = 0
	return nil
}

func sharedAddressProjectScope() ServiceScope {
	return ServiceScope{ProjectServices: true, GatewayNamespace: testNamespace,
		VIPPrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}}
}

func TestAddressInventoryHonorsProjectScope(t *testing.T) {
	for _, tc := range []struct {
		name                                              string
		enabled, ownsVPC, inPool, trustedGateway, allowed bool
	}{
		{"Enabled", true, true, true, true, true},
		{"Disabled", false, true, true, true, false},
		{"ForeignVPC", true, false, true, true, false},
		{"OutsidePool", true, true, false, true, false},
		{"UntrustedGateway", true, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			address, rule := sharedAddressFixture()
			address.Namespace, rule.Namespace = testTenantNamespace, testTenantNamespace
			vpc := newTenantVPC(address.Spec.VPCRef)
			if !tc.ownsVPC {
				vpc.Status.VPC = "someone-else"
			}
			rogue := newTestGateway("rogue-node")
			rogue.Namespace = testTenantNamespace
			c := newTenantClient(t, address, rule, vpc, rogue)
			engine := &ownedTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
			r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
			r.Scope = sharedAddressProjectScope()
			r.Scope.ProjectServices = tc.enabled
			if !tc.inPool {
				r.Scope.VIPPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8:9::/64")}
			}
			namespace := testNamespace
			if !tc.trustedGateway {
				namespace = testTenantNamespace
			}
			inventory, err := r.prepareAddressInventory(ctx, namespace, []api.NetworkService{*rule})
			if err != nil {
				t.Fatal(err)
			}
			if (len(inventory) != 0) != tc.allowed || (len(engine.owned) != 0) != tc.allowed {
				t.Fatalf("allowed=%t inventory=%v guards=%v", tc.allowed, inventory, engine.owned)
			}
		})
	}
}

func TestProjectAddressScopeDisableStillCleansRetirement(t *testing.T) {
	ctx := context.Background()
	address, _ := sharedAddressFixture()
	address.Namespace = testTenantNamespace
	address.Spec.Retired = true
	address.Status.Conditions = []metav1.Condition{{Type: programmedConditionType(testNodeGWA),
		Status: metav1.ConditionTrue, ObservedGeneration: address.Generation, Reason: "PreviouslyServed"}}
	c := fake.NewClientBuilder().WithScheme(newRuleTestScheme(t)).WithStatusSubresource(address).
		WithObjects(address, newTestGateway(testNodeGWA)).Build()
	engine := &ownedTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
	r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
	r.Scope = ServiceScope{GatewayNamespace: testNamespace}
	inventory, err := r.prepareAddressInventory(ctx, testNamespace, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 0 || len(engine.owned) != 0 {
		t.Fatal("disabled project anchor acquired a VIP guard")
	}
	announced, err := r.publishAddressOutcomes(
		ctx, testNamespace, inventory, nil, gateway.EngineStatus{Healthy: true}, testRouterName,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if !addressRetirementAcknowledged(address) || len(announced) != 0 {
		t.Fatalf("disabled cleanup stalled or overwrote active advertisements: %+v %v", address.Status, announced)
	}
}

func TestPreemptiveProjectTombstoneRetiresWithLiveGateway(t *testing.T) {
	ctx := context.Background()
	address, rule := sharedAddressFixture()
	address.Namespace, rule.Namespace = testTenantNamespace, testTenantNamespace
	address.Spec.Retired = true
	address.Spec.VPCRef = ""
	address.Spec.Group.Listeners = nil
	c := fake.NewClientBuilder().WithScheme(newRuleTestScheme(t)).WithStatusSubresource(address).
		WithObjects(address, newTestGateway(testNodeGWA), newTenantVPC(rule.Spec.VPCRef)).Build()
	engine := &ownedTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
	r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
	r.Scope = sharedAddressProjectScope()
	inventory, err := r.prepareAddressInventory(ctx, testNamespace, []api.NetworkService{*rule})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 0 || len(engine.owned) != 0 {
		t.Fatal("preemptive tombstone or delayed source acquired a VIP guard")
	}
	announced, err := r.publishAddressOutcomes(
		ctx, testNamespace, inventory, nil, gateway.EngineStatus{Healthy: true}, testRouterName,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if !addressRetirementAcknowledged(address) || len(announced) != 0 {
		t.Fatalf("preemptive retirement stalled or announced: %+v %v", address.Status, announced)
	}
}

func TestProjectAnchorCannotDisplaceTrustedVIP(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(map[bool]string{false: "Singleton", true: "Grouped"}[grouped], func(t *testing.T) {
			ctx := context.Background()
			address, project := sharedAddressFixture()
			address.Namespace, project.Namespace = testTenantNamespace, testTenantNamespace
			trusted := project.DeepCopy()
			trusted.Namespace = testNamespace
			if !grouped {
				trusted.Spec.AddressGroup = nil
			}
			c := newTenantClient(t, address, project, trusted, newTenantVPC(project.Spec.VPCRef))
			engine := &ownedTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
			r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
			r.Scope = sharedAddressProjectScope()
			inventory, err := r.prepareAddressInventory(ctx, testNamespace, []api.NetworkService{*project})
			if err != nil {
				t.Fatal(err)
			}
			if len(inventory) != 0 || len(engine.owned) != 0 {
				t.Fatal("tenant anchor or fallback rule displaced trusted VIP")
			}
		})
	}
}

func TestDisabledProjectGroupedRuleCanFinishDeletion(t *testing.T) {
	ctx := context.Background()
	address, rule := sharedAddressFixture()
	address.Namespace, rule.Namespace = testTenantNamespace, testTenantNamespace
	address.Spec.Retired = true
	rule.Finalizers = []string{networkRuleFinalizer}
	for _, kind := range []string{programmedConditionType(testNodeGWA), advertisedConditionType(testNodeGWA)} {
		rule.Status.Conditions = append(
			rule.Status.Conditions,
			metav1.Condition{Type: kind, Status: metav1.ConditionTrue,
				ObservedGeneration: rule.Generation, Reason: "PreviouslyServed", LastTransitionTime: metav1.Now()},
		)
	}
	address.Status.Conditions = append([]metav1.Condition(nil), rule.Status.Conditions...)
	binding := newTestServiceVIPBinding(api.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Labels = ruleLabels(rule, testNamespace)
	binding.Labels[bindingNodeLabel] = testComputeNodeName
	binding.Labels[bindingManagedByLabel] = bindingManagedByValue
	binding.Spec.SourceRef = &api.ServiceVIPBindingSourceReference{Namespace: rule.Namespace, Name: rule.Name,
		UID: rule.UID, Generation: rule.Generation, AllocationUID: rule.Spec.AddressGroup.UID}
	c := newIndexedClientBuilder(newRuleTestScheme(t)).
		WithStatusSubresource(&api.NetworkGateway{}, &api.NetworkService{}, &api.NetworkServiceAddress{}).
		WithObjects(address, rule, binding, newTestGateway(testNodeGWA)).Build()
	engine := &ownedTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
	r := newGatewayReconciler(c, c.Scheme(), engine, testNodeGWA)
	r.Scope = ServiceScope{GatewayNamespace: testNamespace}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatal(err)
	}
	if len(engine.lastDesired.Rules) != 0 {
		t.Fatal("disabled rule was programmed")
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(rule), rule); err != nil {
		t.Fatal(err)
	}
	for i := range rule.Status.Conditions {
		if rule.Status.Conditions[i].Type == programmedConditionType(testNodeGWA) ||
			rule.Status.Conditions[i].Type == advertisedConditionType(testNodeGWA) {
			if rule.Status.Conditions[i].Status != metav1.ConditionFalse {
				t.Fatal("historical serving receipt was not withdrawn")
			}
			rule.Status.Conditions[i].LastTransitionTime = metav1.NewTime(time.Now().Add(-2 * time.Second))
		}
	}
	if err := c.Status().Update(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, rule); err != nil {
		t.Fatal(err)
	}
	binder := &NetworkServiceBindingReconciler{
		Client:    c,
		APIReader: c,
		NodeName:  testComputeNodeName,
		Namespace: testNamespace,
	}
	if _, err := binder.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(rule)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(binding), binding); !apierrors.IsNotFound(err) {
		t.Fatalf("binding not removed: %v", err)
	}
	service := &NetworkServiceReconciler{Client: c, APIReader: c, NodeName: testNodeGWA, Scope: r.Scope}
	if _, err := service.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(rule)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(rule), rule); !apierrors.IsNotFound(err) {
		t.Fatalf("rule finalizer stalled: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: testRuleKey(testNodeGWA)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(address), address); err != nil {
		t.Fatal(err)
	}
	if !addressRetirementAcknowledged(address) {
		t.Fatal("retirement stalled after rule/binding teardown")
	}
}
