// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
					Reason:             "Withdrawn",
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
				Reason:             "Withdrawn",
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

func (e *renewalTestEngine) SetBlockedVIPs(_ context.Context, blocked []netip.Addr) error {
	if len(blocked) == 0 {
		e.renewals++
	}
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
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&api.NetworkGateway{}).
				WithObjects(gw).
				Build()
			engine := &renewalTestEngine{fakeGatewayEngine: newFakeGatewayEngine()}
			engine.orphansErr = tc.sweepErr
			r := newGatewayReconciler(c, scheme, engine, testNodeGWA)
			err := r.finishAddressConvergence(
				context.Background(),
				gw,
				gateway.EngineState{},
				gateway.EngineStatus{Healthy: tc.healthy},
				0,
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
