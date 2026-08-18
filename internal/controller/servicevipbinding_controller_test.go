// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testVIPBindingNode        = "vip-node-1"
	testVIPBindingName        = "binding-1"
	testVIPBindingVIPAddr     = "2001:db8:5:5::100"
	testVIPBindingBackendAddr = "fd20:60::5:5"
)

func newTestServiceVIPBinding(
	egressKind bgpv1alpha1.ServiceVIPBindingEgressKind, nodeName string,
) *bgpv1alpha1.ServiceVIPBinding {
	return &bgpv1alpha1.ServiceVIPBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testVIPBindingName},
		Spec: bgpv1alpha1.ServiceVIPBindingSpec{
			TargetRef:      bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: nodeName},
			VIPAddress:     testVIPBindingVIPAddr,
			Port:           8080,
			Protocol:       bgpv1alpha1.NetworkRuleProtocolTCP,
			BackendAddress: testVIPBindingBackendAddr,
			BackendPort:    30080,
			EgressKind:     egressKind,
		},
	}
}

func bindingKey() types.NamespacedName {
	return types.NamespacedName{Namespace: testNamespace, Name: testVIPBindingName}
}

// vipCall records one RegisterIngress/RegisterEgress invocation against
// fakeVIPTable.
type vipCall struct {
	block    uint64
	argument uint16
	proto    uint8
	addr1    net.IP
	port1    uint16
	addr2    net.IP
	port2    uint16
}

// unregisterCall records one UnregisterIngress/UnregisterEgress invocation.
type unregisterCall struct {
	block    uint64
	argument uint16
	proto    uint8
	port     uint16
}

// fakeVIPTable is a fake VIPTranslationTable for testing
// ServiceVIPBindingReconciler's tap branch without a real kernel map.
type fakeVIPTable struct {
	ingressCalls  []vipCall
	egressCalls   []vipCall
	unregIngress  []unregisterCall
	unregEgress   []unregisterCall
	registerErr   error
	unregisterErr error
}

func (f *fakeVIPTable) RegisterIngress(block uint64, argument uint16, proto uint8,
	vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16) error {
	f.ingressCalls = append(f.ingressCalls, vipCall{block, argument, proto, vipAddr, vipPort, backendAddr, backendPort})
	return f.registerErr
}

func (f *fakeVIPTable) RegisterEgress(block uint64, argument uint16, proto uint8,
	backendAddr net.IP, backendPort uint16, vipAddr net.IP, vipPort uint16) error {
	f.egressCalls = append(f.egressCalls, vipCall{block, argument, proto, backendAddr, backendPort, vipAddr, vipPort})
	return f.registerErr
}

func (f *fakeVIPTable) UnregisterIngress(block uint64, argument uint16, proto uint8, vipPort uint16) error {
	f.unregIngress = append(f.unregIngress, unregisterCall{block, argument, proto, vipPort})
	return f.unregisterErr
}

func (f *fakeVIPTable) UnregisterEgress(block uint64, argument uint16, proto uint8, backendPort uint16) error {
	f.unregEgress = append(f.unregEgress, unregisterCall{block, argument, proto, backendPort})
	return f.unregisterErr
}

// stubVIPFns overrides vipBindFn/vipUnbindFn/vipVerifyFn for the duration
// of one test, restoring the real functions on cleanup -- t.Cleanup runs
// even if the test fails, so a later test never observes a stubbed
// function left behind by an earlier one.
func stubVIPFns(t *testing.T, bind, unbind, verify func(net.IP) error) {
	t.Helper()
	origBind, origUnbind, origVerify := vipBindFn, vipUnbindFn, vipVerifyFn
	vipBindFn, vipUnbindFn, vipVerifyFn = bind, unbind, verify
	t.Cleanup(func() { vipBindFn, vipUnbindFn, vipVerifyFn = origBind, origUnbind, origVerify })
}

func TestServiceVIPBindingReconciler_NotMineIsIgnored(t *testing.T) {
	scheme := newRuleTestScheme(t)
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindVeth, "some-other-node")
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(binding).
		Build()

	var bindCalled bool
	stubVIPFns(t,
		func(net.IP) error { bindCalled = true; return nil },
		func(net.IP) error { return nil },
		func(net.IP) error { return nil },
	)

	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testVIPBindingNode}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if bindCalled {
		t.Errorf("vip.Bind was called for a binding not targeting this node")
	}

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := fakeClient.Get(context.Background(), bindingKey(), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if controllerutil.ContainsFinalizer(got, serviceVIPBindingFinalizer) {
		t.Errorf("finalizer was added to a binding not targeting this node")
	}
}

// newVethTestBinding returns a veth-kind ServiceVIPBinding targeting
// testComputeNodeName with BackendAddress overridden to testBackendAddr --
// veth now needs vip_xlat_table registration too (see
// ServiceVIPBindingReconciler's own doc comment), which requires a backend
// address resolvable against newBackendFixtures' advertised prefix, the
// same fixtures the tap tests already use.
func newVethTestBinding() *bgpv1alpha1.ServiceVIPBinding {
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindVeth, testComputeNodeName)
	binding.Spec.BackendAddress = testBackendAddr
	return binding
}

func TestServiceVIPBindingReconciler_VethBindSuccess(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	binding := newVethTestBinding()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	var boundAddr net.IP
	stubVIPFns(t,
		func(addr net.IP) error { boundAddr = addr; return nil },
		func(net.IP) error { return nil },
		func(net.IP) error { return nil },
	)

	table := &fakeVIPTable{}
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	if boundAddr == nil || !boundAddr.Equal(net.ParseIP(testVIPBindingVIPAddr)) {
		t.Errorf("vip.Bind called with %v, want %s", boundAddr, testVIPBindingVIPAddr)
	}
	// The actual fix: veth must ALSO register vip_xlat_table rows, not just
	// vip.Bind -- see ServiceVIPBindingReconciler's own doc comment for why
	// vip.Bind alone never delivered anything to a VRF-isolated backend pod.
	if len(table.ingressCalls) != 1 || len(table.egressCalls) != 1 {
		t.Fatalf("ingressCalls=%d egressCalls=%d, want 1 each (veth must register vip_xlat_table too)",
			len(table.ingressCalls), len(table.egressCalls))
	}

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := fakeClient.Get(context.Background(), bindingKey(), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !controllerutil.ContainsFinalizer(got, serviceVIPBindingFinalizer) {
		t.Errorf("finalizer was not added")
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound) {
		t.Errorf("Bound condition = %+v, want True", got.Status.Conditions)
	}
}

// TestServiceVIPBindingReconciler_VethNilTableFails mirrors
// TestServiceVIPBindingReconciler_TapNilTableFails: veth now needs
// VIPTranslationTable too, not just for tap.
func TestServiceVIPBindingReconciler_VethNilTableFails(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	binding := newVethTestBinding()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	stubVIPFns(t,
		func(net.IP) error { return nil },
		func(net.IP) error { return nil },
		func(net.IP) error { return nil },
	)

	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName} // no VIPTranslationTable
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err == nil {
		t.Fatal("Reconcile: expected an error binding a veth-kind ServiceVIPBinding with no VIPTranslationTable")
	}
}

func TestServiceVIPBindingReconciler_VethUnbindOnDelete(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	binding := newVethTestBinding()
	controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
	now := metav1.Now()
	binding.DeletionTimestamp = &now

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	var unboundAddr net.IP
	stubVIPFns(t,
		func(net.IP) error { return nil },
		func(addr net.IP) error { unboundAddr = addr; return nil },
		func(net.IP) error { return nil },
	)

	table := &fakeVIPTable{}
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	if unboundAddr == nil || !unboundAddr.Equal(net.ParseIP(testVIPBindingVIPAddr)) {
		t.Errorf("vip.Unbind called with %v, want %s", unboundAddr, testVIPBindingVIPAddr)
	}
	if len(table.unregIngress) != 1 || len(table.unregEgress) != 1 {
		t.Fatalf("unregIngress=%d unregEgress=%d, want 1 each (veth must unregister vip_xlat_table too)",
			len(table.unregIngress), len(table.unregEgress))
	}

	// Removing the last finalizer from an object that already carries a
	// DeletionTimestamp lets the (fake, like the real API server) client
	// actually delete it from the store -- so the only observable proof
	// the finalizer is gone is that the object is gone too.
	got := &bgpv1alpha1.ServiceVIPBinding{}
	err := fakeClient.Get(context.Background(), bindingKey(), got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get: got err=%v, want NotFound (finalizer removal should let deletion complete)", err)
	}
}

// TestServiceVIPBindingReconciler_FinalizerKeptWhenUnbindFails covers the
// "finalizer add/remove ordering" requirement: a failing unbind/unregister
// must never let the finalizer be removed, so the object stays present
// (blocking deletion, and retried) rather than silently leaking host/kernel
// state. VIPTranslationTable is a working fake here so only vip.Unbind's
// own failure is under test.
func TestServiceVIPBindingReconciler_FinalizerKeptWhenUnbindFails(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	binding := newVethTestBinding()
	controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
	now := metav1.Now()
	binding.DeletionTimestamp = &now

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	stubVIPFns(t,
		func(net.IP) error { return nil },
		func(net.IP) error { return errors.New("intentional unbind failure") },
		func(net.IP) error { return nil },
	)

	table := &fakeVIPTable{}
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err == nil {
		t.Fatal("Reconcile: expected an error when vip.Unbind fails")
	}

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := fakeClient.Get(context.Background(), bindingKey(), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !controllerutil.ContainsFinalizer(got, serviceVIPBindingFinalizer) {
		t.Errorf("finalizer was removed despite a failed unbind")
	}
}

func TestServiceVIPBindingReconciler_TapRegisterSuccess(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.BackendAddress = testBackendAddr // must resolve via the fixtures' advertised prefix

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	table := &fakeVIPTable{}
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	if len(table.ingressCalls) != 1 || len(table.egressCalls) != 1 {
		t.Fatalf("ingressCalls=%d egressCalls=%d, want 1 each", len(table.ingressCalls), len(table.egressCalls))
	}
	wantArgument := uint16(testBackendVRFID)
	if table.ingressCalls[0].argument != wantArgument {
		t.Errorf("ingress argument = %d, want %d", table.ingressCalls[0].argument, wantArgument)
	}
	if !table.ingressCalls[0].addr1.Equal(net.ParseIP(testVIPBindingVIPAddr)) {
		t.Errorf("ingress row vip addr = %v, want %s", table.ingressCalls[0].addr1, testVIPBindingVIPAddr)
	}
	if !table.ingressCalls[0].addr2.Equal(net.ParseIP(testBackendAddr)) {
		t.Errorf("ingress row value addr = %v, want %s (backend)", table.ingressCalls[0].addr2, testBackendAddr)
	}

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := fakeClient.Get(context.Background(), bindingKey(), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound) {
		t.Errorf("Bound condition = %+v, want True", got.Status.Conditions)
	}
}

func TestServiceVIPBindingReconciler_TapUnregisterOnDelete(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.BackendAddress = testBackendAddr
	controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
	now := metav1.Now()
	binding.DeletionTimestamp = &now

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	table := &fakeVIPTable{}
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}

	if len(table.unregIngress) != 1 || len(table.unregEgress) != 1 {
		t.Fatalf("unregIngress=%d unregEgress=%d, want 1 each", len(table.unregIngress), len(table.unregEgress))
	}

	// See the same note in TestServiceVIPBindingReconciler_VethUnbindOnDelete:
	// finalizer removal here completes the deletion, so NotFound is the
	// success signal, not a successful Get.
	got := &bgpv1alpha1.ServiceVIPBinding{}
	err := fakeClient.Get(context.Background(), bindingKey(), got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get: got err=%v, want NotFound (finalizer removal should let deletion complete)", err)
	}
}

func TestServiceVIPBindingReconciler_TapNilTableFails(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.BackendAddress = testBackendAddr

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName} // no VIPTranslationTable
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err == nil {
		t.Fatal("Reconcile: expected an error binding a tap-kind ServiceVIPBinding with no VIPTranslationTable")
	}
}

func TestResolveVIPBindingContext_Success(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv, vrf).Build()

	block, argument, err := resolveVIPBindingContext(
		context.Background(), fakeClient, testNamespace, testComputeNodeName, netip.MustParseAddr(testBackendAddr))
	if err != nil {
		t.Fatalf("resolveVIPBindingContext: unexpected error: %v", err)
	}
	if argument != uint16(testBackendVRFID) {
		t.Errorf("argument = %d, want %d", argument, testBackendVRFID)
	}
	if block == 0 {
		t.Errorf("block = 0, want the uSID Block derived from %s", testBackendLocator)
	}
}

func TestResolveVIPBindingContext_NoMatchingVRF(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv, vrf).Build()

	if _, _, err := resolveVIPBindingContext(
		context.Background(), fakeClient, testNamespace, testComputeNodeName, netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("resolveVIPBindingContext: expected an error for an address with no matching advertised prefix")
	}
}

// TestResolveVIPBindingContext_AmbiguousFailsClosed covers the documented
// ambiguity: two local BGPVRFInstances on the same node both advertise a
// prefix containing the same backend address (e.g. two tenants using the
// same ULA range) -- resolveVIPBindingContext must fail rather than guess.
func TestResolveVIPBindingContext_AmbiguousFailsClosed(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)

	vrfID2 := int32(testBackendVRFID + 1)
	function := bgpv1alpha1.SRv6FunctionEndDT46
	adv2 := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "second-adv"},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testBackendRouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{testBackendPrefix}, // same prefix, colliding
			VRFID:         &vrfID2,
			Function:      &function,
		},
	}
	vrf2 := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "second-vrf"},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: testBackendRouterName}},
			VRFID:              vrfID2,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTargetValue}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTargetValue}},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv, vrf, adv2, vrf2).Build()

	_, _, err := resolveVIPBindingContext(
		context.Background(), fakeClient, testNamespace, testComputeNodeName, netip.MustParseAddr(testBackendAddr))
	if err == nil {
		t.Fatal("resolveVIPBindingContext: expected a fail-closed error for ambiguous VRF ownership")
	}
}
