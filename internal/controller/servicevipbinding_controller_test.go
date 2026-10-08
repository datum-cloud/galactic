// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
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
			VPCRef:         testVPCRef,
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

// unregisterBindingCall records one UnregisterBinding invocation.
type unregisterBindingCall struct {
	proto       uint8
	vipAddr     net.IP
	vipPort     uint16
	backendAddr net.IP
	backendPort uint16
}

// unregisterAtCall records one UnregisterBindingAt invocation.
type unregisterAtCall struct {
	block    uint64
	argument uint16
	unregisterBindingCall
}

// unregisterCall records one UnregisterIngress/UnregisterEgress invocation.
type unregisterCall struct {
	block    uint64
	argument uint16
	proto    uint8
	addr     net.IP
	port     uint16
}

// fakeRowKey is one row of fakeVIPTable's simulated vip_xlat_table, ignoring
// the VRF, which every test here shares. slot is 0 on an egress row.
type fakeRowKey struct {
	egress bool
	slot   uint16
	addr   string
	port   uint16
}

// fakeRowValue is the rewrite target a simulated row holds.
type fakeRowValue struct {
	addr string
	port uint16
}

// fakeVIPTable is a fake VIPTranslationTable for testing
// ServiceVIPBindingReconciler's tap branch without a real kernel map. It
// records every call, and rows mirrors what the kernel map would hold,
// including the value checks UnregisterBinding and UnregisterBindingAt make.
type fakeVIPTable struct {
	ingressCalls  []vipCall
	egressCalls   []vipCall
	unregIngress  []unregisterCall
	unregEgress   []unregisterCall
	unregBinding  []unregisterBindingCall
	unregAt       []unregisterAtCall
	registerErr   error
	unregisterErr error
	rows          map[fakeRowKey]fakeRowValue
}

func (f *fakeVIPTable) put(k fakeRowKey, addr net.IP, port uint16) {
	if f.rows == nil {
		f.rows = make(map[fakeRowKey]fakeRowValue)
	}
	f.rows[k] = fakeRowValue{addr.String(), port}
}

func (f *fakeVIPTable) RegisterIngress(block uint64, argument, slot uint16, proto uint8,
	vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16) error {
	f.ingressCalls = append(f.ingressCalls, vipCall{block, argument, proto, vipAddr, vipPort, backendAddr, backendPort})
	if f.registerErr == nil {
		f.put(fakeRowKey{slot: slot, addr: vipAddr.String(), port: vipPort}, backendAddr, backendPort)
	}
	return f.registerErr
}

func (f *fakeVIPTable) RegisterEgress(block uint64, argument uint16, proto uint8,
	backendAddr net.IP, backendPort uint16, vipAddr net.IP, vipPort uint16) error {
	f.egressCalls = append(f.egressCalls, vipCall{block, argument, proto, backendAddr, backendPort, vipAddr, vipPort})
	if f.registerErr == nil {
		f.put(fakeRowKey{egress: true, addr: backendAddr.String(), port: backendPort}, vipAddr, vipPort)
	}
	return f.registerErr
}

func (f *fakeVIPTable) UnregisterIngress(
	block uint64, argument, slot uint16, proto uint8, vipAddr net.IP, vipPort uint16,
) error {
	f.unregIngress = append(f.unregIngress, unregisterCall{block, argument, proto, vipAddr, vipPort})
	if f.unregisterErr == nil {
		delete(f.rows, fakeRowKey{slot: slot, addr: vipAddr.String(), port: vipPort})
	}
	return f.unregisterErr
}

func (f *fakeVIPTable) UnregisterEgress(
	block uint64, argument uint16, proto uint8, backendAddr net.IP, backendPort uint16,
) error {
	f.unregEgress = append(f.unregEgress, unregisterCall{block, argument, proto, backendAddr, backendPort})
	if f.unregisterErr == nil {
		delete(f.rows, fakeRowKey{egress: true, addr: backendAddr.String(), port: backendPort})
	}
	return f.unregisterErr
}

// removeOwnRows deletes the binding's two rows where they still hold its
// values, as vipxlatmap's removal by value does.
func (f *fakeVIPTable) removeOwnRows(
	slot uint16, vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16,
) {
	in := fakeRowKey{slot: slot, addr: vipAddr.String(), port: vipPort}
	if f.rows[in] == (fakeRowValue{backendAddr.String(), backendPort}) {
		delete(f.rows, in)
	}
	out := fakeRowKey{egress: true, addr: backendAddr.String(), port: backendPort}
	if f.rows[out] == (fakeRowValue{vipAddr.String(), vipPort}) {
		delete(f.rows, out)
	}
}

func (f *fakeVIPTable) UnregisterBindingAt(block uint64, argument, slot uint16, proto uint8,
	vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16) ([]vipxlatmap.Entry, error) {
	f.unregAt = append(f.unregAt, unregisterAtCall{
		block, argument, unregisterBindingCall{proto, vipAddr, vipPort, backendAddr, backendPort}})
	if f.unregisterErr == nil {
		f.removeOwnRows(slot, vipAddr, vipPort, backendAddr, backendPort)
	}
	return nil, f.unregisterErr
}

func (f *fakeVIPTable) UnregisterBinding(slot uint16, proto uint8, vipAddr net.IP, vipPort uint16,
	backendAddr net.IP, backendPort uint16) ([]vipxlatmap.Entry, error) {
	f.unregBinding = append(f.unregBinding, unregisterBindingCall{proto, vipAddr, vipPort, backendAddr, backendPort})
	if f.unregisterErr == nil {
		f.removeOwnRows(slot, vipAddr, vipPort, backendAddr, backendPort)
	}
	return nil, f.unregisterErr
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
	adv.Spec.Prefixes = append(adv.Spec.Prefixes, testIPv6BackendPrefix)
	binding := newVethTestBinding()
	binding.Spec.BackendAddress = testVIPBindingBackendAddr
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
	if len(table.unregBinding) != 1 || len(table.unregAt) != 1 {
		t.Fatalf("unregBinding=%d unregAt=%d, want 1 each (veth must unregister vip_xlat_table too)",
			len(table.unregBinding), len(table.unregAt))
	}
	if table.unregAt[0].argument != uint16(testBackendVRFID) {
		t.Errorf("UnregisterBindingAt argument = %d, want %d", table.unregAt[0].argument, testBackendVRFID)
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
	adv.Spec.Prefixes = append(adv.Spec.Prefixes, testIPv6BackendPrefix)
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.BackendAddress = testVIPBindingBackendAddr
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

	if len(table.unregBinding) != 1 || len(table.unregAt) != 1 {
		t.Fatalf("unregBinding=%d unregAt=%d, want 1 each", len(table.unregBinding), len(table.unregAt))
	}
	if table.unregAt[0].argument != uint16(testBackendVRFID) {
		t.Errorf("UnregisterBindingAt argument = %d, want %d", table.unregAt[0].argument, testBackendVRFID)
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

// TestServiceVIPBindingReconciler_DeleteAfterVRFGone covers #750: once the
// binding's VPC has left the node, its BGPVRFInstance and BGPAdvertisement are
// gone and the VRF context no longer resolves. Deletion must still remove the
// vip_xlat_table rows, by value, and release the finalizer.
func TestServiceVIPBindingReconciler_DeleteAfterVRFGone(t *testing.T) {
	for _, kind := range []bgpv1alpha1.ServiceVIPBindingEgressKind{
		bgpv1alpha1.ServiceVIPBindingEgressKindTap,
		bgpv1alpha1.ServiceVIPBindingEgressKindVeth,
	} {
		t.Run(string(kind), func(t *testing.T) {
			scheme := newRuleTestScheme(t)
			router, _, _ := newBackendFixtures(testVPCRef)                 // the VPC's adv and vrf are gone
			binding := newTestServiceVIPBinding(kind, testComputeNodeName) // IPv6 VIP and backend
			controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
			now := metav1.Now()
			binding.DeletionTimestamp = &now

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
				WithObjects(router, binding).
				Build()

			stubVIPFns(t,
				func(net.IP) error { return nil },
				func(net.IP) error { return nil },
				func(net.IP) error { return nil },
			)

			table := &fakeVIPTable{}
			r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
				t.Fatalf("Reconcile: unexpected error: %v", err)
			}

			if len(table.unregBinding) != 1 {
				t.Fatalf("UnregisterBinding called %d times, want 1", len(table.unregBinding))
			}
			call := table.unregBinding[0]
			if call.proto != ipProtoTCP || call.vipPort != 8080 || call.backendPort != 30080 ||
				!call.vipAddr.Equal(net.ParseIP(testVIPBindingVIPAddr)) ||
				!call.backendAddr.Equal(net.ParseIP(testVIPBindingBackendAddr)) {
				t.Errorf("UnregisterBinding call = %+v, want the binding's proto, VIP, and backend", call)
			}
			if len(table.unregAt) != 0 {
				t.Errorf("UnregisterBindingAt called %d times, want 0 (no VRF context to check)", len(table.unregAt))
			}

			got := &bgpv1alpha1.ServiceVIPBinding{}
			err := fakeClient.Get(context.Background(), bindingKey(), got)
			if !apierrors.IsNotFound(err) {
				t.Fatalf("get: got err=%v, want NotFound (finalizer removal should let deletion complete)", err)
			}
		})
	}
}

// TestServiceVIPBindingReconciler_FinalizerKeptWhenRowRemovalFails checks that
// a kernel delete failure still blocks deletion, even with no VRF context.
func TestServiceVIPBindingReconciler_FinalizerKeptWhenRowRemovalFails(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, _, _ := newBackendFixtures(testVPCRef)
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
	now := metav1.Now()
	binding.DeletionTimestamp = &now

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, binding).
		Build()

	table := &fakeVIPTable{unregisterErr: errors.New("intentional delete failure")}
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err == nil {
		t.Fatal("Reconcile: expected an error when removing the rows fails")
	}

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := fakeClient.Get(context.Background(), bindingKey(), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !controllerutil.ContainsFinalizer(got, serviceVIPBindingFinalizer) {
		t.Errorf("finalizer was removed despite a failed row removal")
	}
}

// TestServiceVIPBindingReconciler_DeleteSkipsAddressesWithNoRows covers
// bindings registration never wrote rows for: an IPv4 backend, which the CRD
// accepts and vip_xlat_table does not, or an unset one. With the VRF gone too,
// deletion must still finish without looking for rows by value.
func TestServiceVIPBindingReconciler_DeleteSkipsAddressesWithNoRows(t *testing.T) {
	for name, backend := range map[string]string{"ipv4": "10.0.0.1", "unset": ""} {
		t.Run(name, func(t *testing.T) {
			scheme := newRuleTestScheme(t)
			router, _, _ := newBackendFixtures(testVPCRef)
			binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
			binding.Spec.BackendAddress = backend
			controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
			now := metav1.Now()
			binding.DeletionTimestamp = &now

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
				WithObjects(router, binding).
				Build()

			table := &fakeVIPTable{}
			r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
				t.Fatalf("Reconcile: unexpected error: %v", err)
			}
			if len(table.unregBinding) != 0 {
				t.Errorf("UnregisterBinding called %d times, want 0", len(table.unregBinding))
			}

			got := &bgpv1alpha1.ServiceVIPBinding{}
			err := fakeClient.Get(context.Background(), bindingKey(), got)
			if !apierrors.IsNotFound(err) {
				t.Fatalf("get: got err=%v, want NotFound (finalizer removal should let deletion complete)", err)
			}
		})
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
		context.Background(), fakeClient, testNamespace, testComputeNodeName, testVPCRef)
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

func TestResolveVIPBindingContext_NoVRFForVPC(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv, vrf).Build()

	for _, vpcRef := range []string{"vpc-absent", ""} {
		if _, _, err := resolveVIPBindingContext(
			context.Background(), fakeClient, testNamespace, testComputeNodeName, vpcRef); err == nil {
			t.Errorf("resolveVIPBindingContext(vpcRef %q): expected an error for a VPC with no VRF on this node", vpcRef)
		}
	}
}

// TestResolveVIPBindingContext_CollidingTenantsResolveToTheirOwnVRF covers two
// tenants on one node advertising the same prefix, such as two VPCs choosing
// the same ULA range. Each binding names its VPC, so each resolves to its own
// VRF rather than failing as ambiguous or picking the other tenant's.
func TestResolveVIPBindingContext_CollidingTenantsResolveToTheirOwnVRF(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	_, adv2, vrf2 := newBackendFixtures("vpc-2")
	vrf2.Spec.VRFID = testBackendVRFID + 1
	adv2.Spec.VRFID = ptr(int32(testBackendVRFID + 1))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router, adv, vrf, adv2, vrf2).Build()

	for vpcRef, want := range map[string]uint16{testVPCRef: testBackendVRFID, "vpc-2": testBackendVRFID + 1} {
		_, argument, err := resolveVIPBindingContext(
			context.Background(), fakeClient, testNamespace, testComputeNodeName, vpcRef)
		if err != nil {
			t.Fatalf("resolveVIPBindingContext(%s): %v", vpcRef, err)
		}
		if argument != want {
			t.Errorf("resolveVIPBindingContext(%s) argument = %d, want %d", vpcRef, argument, want)
		}
	}
}

// TestServiceVIPBindingReconciler_BackendMustBeAdvertised checks that a
// binding is programmed only for a backend address its own VRF advertises on
// this node. The VRF resolves by vpcRef in every case.
func TestServiceVIPBindingReconciler_BackendMustBeAdvertised(t *testing.T) {
	tests := []struct {
		name      string
		backend   string
		otherVRF  bool // vpc-2 has a VRF on this node advertising testIPv6BackendPrefix
		wantBound bool
	}{
		{name: "address in an advertised prefix", backend: testBackendAddr, wantBound: true},
		{name: "address in no advertised prefix", backend: testVIPBindingBackendAddr},
		{name: "prefix advertised by another VRF on the node", backend: testVIPBindingBackendAddr, otherVRF: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newRuleTestScheme(t)
			router, adv, vrf := newBackendFixtures(testVPCRef) // advertises testBackendPrefix only
			binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
			binding.Spec.BackendAddress = tt.backend

			objs := []client.Object{router, adv, vrf, binding}
			if tt.otherVRF {
				_, adv2, vrf2 := newBackendFixtures("vpc-2")
				vrf2.Spec.VRFID = testBackendVRFID + 1
				adv2.Spec.VRFID = ptr(int32(testBackendVRFID + 1))
				adv2.Spec.Prefixes = []bgpv1alpha1.Prefix{testIPv6BackendPrefix}
				objs = append(objs, adv2, vrf2)
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
				WithObjects(objs...).
				Build()

			table := &fakeVIPTable{}
			r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
			_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()})
			if tt.wantBound != (err == nil) {
				t.Fatalf("Reconcile error = %v, want error %t", err, !tt.wantBound)
			}

			wantCalls, wantReason := 0, "BindFailed"
			if tt.wantBound {
				wantCalls, wantReason = 1, reasonBindingsBound
			}
			if len(table.ingressCalls) != wantCalls || len(table.egressCalls) != wantCalls {
				t.Errorf("ingressCalls=%d egressCalls=%d, want %d each",
					len(table.ingressCalls), len(table.egressCalls), wantCalls)
			}

			got := &bgpv1alpha1.ServiceVIPBinding{}
			if err := fakeClient.Get(context.Background(), bindingKey(), got); err != nil {
				t.Fatalf("get: %v", err)
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound)
			if cond == nil {
				t.Fatal("Bound condition not set")
			}
			if cond.Reason != wantReason {
				t.Errorf("Bound reason = %q (%s), want %q", cond.Reason, cond.Message, wantReason)
			}
			if !tt.wantBound && !strings.Contains(cond.Message, tt.backend) {
				t.Errorf("Bound message = %q, want it to name backend address %s", cond.Message, tt.backend)
			}
		})
	}
}

// TestServiceVIPBindingReconciler_DeleteAfterAdvertisementGone checks that
// teardown does not require the backend's advertisement: with the VRF still
// on the node but its advertisement gone, both removal passes run and the
// finalizer is released.
func TestServiceVIPBindingReconciler_DeleteAfterAdvertisementGone(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, _, vrf := newBackendFixtures(testVPCRef) // no advertisement
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
	now := metav1.Now()
	binding.DeletionTimestamp = &now

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, vrf, binding).
		Build()

	table := &fakeVIPTable{}
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	if len(table.unregBinding) != 1 || len(table.unregAt) != 1 {
		t.Fatalf("unregBinding=%d unregAt=%d, want 1 each", len(table.unregBinding), len(table.unregAt))
	}
	if table.unregAt[0].argument != uint16(testBackendVRFID) {
		t.Errorf("UnregisterBindingAt argument = %d, want %d", table.unregAt[0].argument, testBackendVRFID)
	}
	err := fakeClient.Get(context.Background(), bindingKey(), &bgpv1alpha1.ServiceVIPBinding{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get: got err=%v, want NotFound (finalizer removal should let deletion complete)", err)
	}
}

// TestServiceVIPBinding_AdvertisementRequests: an advertisement on this node's
// router requeues this node's bindings only, and one on another node's router
// or naming no known router requeues nothing.
func TestServiceVIPBinding_AdvertisementRequests(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, _ := newBackendFixtures(testVPCRef)
	otherRouter := router.DeepCopy()
	otherRouter.Name = "other-router"
	otherRouter.Spec.TargetRef.Name = "unserved-node"
	otherAdv := adv.DeepCopy()
	otherAdv.Name = "other-adv"
	otherAdv.Spec.RouterRef.Name = otherRouter.Name
	orphanAdv := adv.DeepCopy()
	orphanAdv.Name = "orphan-adv"
	orphanAdv.Spec.RouterRef.Name = "absent-router"

	mine := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	elsewhere := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, "unserved-node")
	elsewhere.Name = "binding-elsewhere"

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(router, otherRouter, mine, elsewhere).
		Build()
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName}

	reqs := r.advertisementRequests(context.Background(), adv)
	if len(reqs) != 1 || reqs[0].NamespacedName != bindingKey() {
		t.Errorf("advertisementRequests(this node's adv) = %v, want [%s]", reqs, bindingKey())
	}
	for _, a := range []*bgpv1alpha1.BGPAdvertisement{otherAdv, orphanAdv} {
		if reqs := r.advertisementRequests(context.Background(), a); len(reqs) != 0 {
			t.Errorf("advertisementRequests(%s) = %v, want none", a.Name, reqs)
		}
	}
}
