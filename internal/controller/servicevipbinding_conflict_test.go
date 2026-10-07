// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Both backends fall inside testIPv6BackendPrefix, which newConflictReconciler
// adds to newBackendFixtures' advertisement, so both bindings below resolve to
// the same VRF.
const (
	testConflictBackendA = "fd20:60::a"
	testConflictBackendB = "fd20:60::b"
	testConflictVIPA     = "2001:db8:5:5::a"
	testConflictVIPB     = "2001:db8:5:5::b"

	testConflictOld   = "old"
	testConflictYoung = "young"
)

// newConflictBinding returns a tap-kind binding on testComputeNodeName, created
// age seconds before a fixed reference time.
func newConflictBinding(name, vipAddr, backendAddr string, age int) *bgpv1alpha1.ServiceVIPBinding {
	b := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	b.Name = name
	b.Spec.VIPAddress = vipAddr
	b.Spec.BackendAddress = backendAddr
	b.Spec.Port = 443
	b.Spec.BackendPort = 8443
	ref := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	b.CreationTimestamp = metav1.NewTime(ref.Add(-time.Duration(age) * time.Second))
	return b
}

func markDeleting(b *bgpv1alpha1.ServiceVIPBinding) {
	controllerutil.AddFinalizer(b, serviceVIPBindingFinalizer)
	now := metav1.Now()
	b.DeletionTimestamp = &now
}

func newConflictReconciler(
	t *testing.T, table *fakeVIPTable, objs ...client.Object,
) (*ServiceVIPBindingReconciler, client.Client) {
	t.Helper()
	router, adv, vrf := newBackendFixtures(testVPCRef)
	adv.Spec.Prefixes = append(adv.Spec.Prefixes, testIPv6BackendPrefix)
	c := fake.NewClientBuilder().
		WithScheme(newRuleTestScheme(t)).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(append([]client.Object{router, adv, vrf}, objs...)...).
		Build()
	return &ServiceVIPBindingReconciler{Client: c, NodeName: testComputeNodeName, VIPTranslationTable: table}, c
}

func reconcileBinding(t *testing.T, r *ServiceVIPBindingReconciler, name string) {
	t.Helper()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: name}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile(%s): unexpected error: %v", name, err)
	}
}

func boundCondition(t *testing.T, c client.Client, name string) *metav1.Condition {
	t.Helper()
	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: name}, got); err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	return meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound)
}

func ingressRow(vip string) fakeRowKey {
	return fakeRowKey{addr: net.ParseIP(vip).String(), port: 443}
}

func egressRow(backend string) fakeRowKey {
	return fakeRowKey{egress: true, addr: net.ParseIP(backend).String(), port: 8443}
}

// TestServiceVIPBinding_SharedPortDistinctVIPsBothBind: two VIPs in one VPC on
// the same port and protocol each get their own rows.
func TestServiceVIPBinding_SharedPortDistinctVIPsBothBind(t *testing.T) {
	a := newConflictBinding("a", testConflictVIPA, testConflictBackendA, 20)
	b := newConflictBinding("b", testConflictVIPB, testConflictBackendB, 10)
	table := &fakeVIPTable{}
	r, c := newConflictReconciler(t, table, a, b)

	reconcileBinding(t, r, "a")
	reconcileBinding(t, r, "b")

	for _, name := range []string{"a", "b"} {
		if cond := boundCondition(t, c, name); cond == nil || cond.Status != metav1.ConditionTrue {
			t.Errorf("binding %s Bound = %+v, want True", name, cond)
		}
	}
	want := map[fakeRowKey]string{
		ingressRow(testConflictVIPA):    net.ParseIP(testConflictBackendA).String(),
		ingressRow(testConflictVIPB):    net.ParseIP(testConflictBackendB).String(),
		egressRow(testConflictBackendA): net.ParseIP(testConflictVIPA).String(),
		egressRow(testConflictBackendB): net.ParseIP(testConflictVIPB).String(),
	}
	if len(table.rows) != len(want) {
		t.Fatalf("rows = %v, want %v", table.rows, want)
	}
	for k, v := range want {
		if table.rows[k].addr != v {
			t.Errorf("row %+v = %q, want %q", k, table.rows[k].addr, v)
		}
	}
}

// TestServiceVIPBinding_SameVIPPortConflicts: a younger binding claiming an
// older binding's VIP and port is not programmed and reports Conflict, and the
// older binding's rows are untouched, whichever reconciles first.
func TestServiceVIPBinding_SameVIPPortConflicts(t *testing.T) {
	for _, order := range [][]string{{testConflictOld, testConflictYoung}, {testConflictYoung, testConflictOld}} {
		t.Run(order[0]+"-first", func(t *testing.T) {
			old := newConflictBinding(testConflictOld, testConflictVIPA, testConflictBackendA, 20)
			young := newConflictBinding(testConflictYoung, testConflictVIPA, testConflictBackendB, 10)
			table := &fakeVIPTable{}
			r, c := newConflictReconciler(t, table, old, young)

			for _, name := range order {
				reconcileBinding(t, r, name)
			}

			if cond := boundCondition(t, c, testConflictOld); cond == nil || cond.Status != metav1.ConditionTrue {
				t.Errorf("old Bound = %+v, want True", cond)
			}
			cond := boundCondition(t, c, testConflictYoung)
			if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "Conflict" {
				t.Fatalf("young Bound = %+v, want False/Conflict", cond)
			}
			assertRowRewrite(t, table, ingressRow(testConflictVIPA), testConflictBackendA, "VIP A ingress row")
			if _, ok := table.rows[egressRow(testConflictBackendB)]; ok {
				t.Errorf("young's egress row is present, want absent: a binding in conflict writes neither row")
			}
			for _, call := range table.ingressCalls {
				if call.addr2.Equal(net.ParseIP(testConflictBackendB)) {
					t.Errorf("young registered an ingress row: %+v", call)
				}
			}
		})
	}
}

// TestServiceVIPBinding_DeletingConflictedBindingKeepsOwnerRow: deleting the
// binding in conflict leaves the owner's shared row in place.
func TestServiceVIPBinding_DeletingConflictedBindingKeepsOwnerRow(t *testing.T) {
	old := newConflictBinding(testConflictOld, testConflictVIPA, testConflictBackendA, 20)
	young := newConflictBinding(testConflictYoung, testConflictVIPA, testConflictBackendB, 10)
	table := &fakeVIPTable{}
	r, c := newConflictReconciler(t, table, old, young)
	reconcileBinding(t, r, testConflictOld)
	reconcileBinding(t, r, testConflictYoung)

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := c.Get(context.Background(), conflictKey(testConflictYoung), got); err != nil {
		t.Fatalf("get young: %v", err)
	}
	if err := c.Delete(context.Background(), got); err != nil {
		t.Fatalf("delete young: %v", err)
	}
	reconcileBinding(t, r, testConflictYoung)

	assertRowRewrite(t, table, ingressRow(testConflictVIPA), testConflictBackendA, "VIP A ingress row")
	if _, ok := table.rows[egressRow(testConflictBackendA)]; !ok {
		t.Errorf("old's egress row is gone after deleting young")
	}
	err := c.Get(context.Background(), conflictKey(testConflictYoung), got)
	if !apierrors.IsNotFound(err) {
		t.Errorf("get young: err=%v, want NotFound (deletion should complete)", err)
	}
}

// TestServiceVIPBinding_DeletingOwnerHandsRowOver: deleting the owner removes
// its rows, and the binding in conflict then takes the shared row over.
func TestServiceVIPBinding_DeletingOwnerHandsRowOver(t *testing.T) {
	old := newConflictBinding(testConflictOld, testConflictVIPA, testConflictBackendA, 20)
	young := newConflictBinding(testConflictYoung, testConflictVIPA, testConflictBackendB, 10)
	table := &fakeVIPTable{}
	r, c := newConflictReconciler(t, table, old, young)
	reconcileBinding(t, r, testConflictOld)
	reconcileBinding(t, r, testConflictYoung)

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := c.Get(context.Background(), conflictKey(testConflictOld), got); err != nil {
		t.Fatalf("get old: %v", err)
	}
	if err := c.Delete(context.Background(), got); err != nil {
		t.Fatalf("delete old: %v", err)
	}
	reconcileBinding(t, r, testConflictOld)

	if _, ok := table.rows[egressRow(testConflictBackendA)]; ok {
		t.Errorf("old's own egress row survived its deletion")
	}

	reconcileBinding(t, r, testConflictYoung)
	if cond := boundCondition(t, c, testConflictYoung); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("young Bound = %+v after old's deletion, want True", cond)
	}
	assertRowRewrite(t, table, ingressRow(testConflictVIPA), testConflictBackendB, "VIP A ingress row")
	assertRowRewrite(t, table, egressRow(testConflictBackendB), testConflictVIPA, "young's egress row")
}

// TestServiceVIPBinding_VethUnbindKeepsSharedVIP: deleting a veth binding
// leaves the VIP on the dummy interface while another binding for a different
// port of the same VIP is live.
func TestServiceVIPBinding_VethUnbindKeepsSharedVIP(t *testing.T) {
	https := newConflictBinding("https", testConflictVIPA, testConflictBackendA, 20)
	https.Spec.EgressKind = bgpv1alpha1.ServiceVIPBindingEgressKindVeth
	http := newConflictBinding("http", testConflictVIPA, testConflictBackendA, 10)
	http.Spec.EgressKind = bgpv1alpha1.ServiceVIPBindingEgressKindVeth
	http.Spec.Port = 80
	http.Spec.BackendPort = 8080
	markDeleting(http)

	var unbound []net.IP
	stubVIPFns(t,
		func(net.IP) error { return nil },
		func(addr net.IP) error { unbound = append(unbound, addr); return nil },
		func(net.IP) error { return nil },
	)

	table := &fakeVIPTable{}
	r, _ := newConflictReconciler(t, table, https, http)
	reconcileBinding(t, r, "http")

	if len(unbound) != 0 {
		t.Errorf("vip.Unbind called with %v, want no call while binding https still uses the VIP", unbound)
	}
	if len(table.unregBinding) != 1 || len(table.unregAt) != 1 {
		t.Errorf("unregBinding=%d unregAt=%d, want 1 each (http's own rows)",
			len(table.unregBinding), len(table.unregAt))
	}
}

// TestServiceVIPBinding_NodePeerRequests: a binding on this node requeues every
// other binding on this node, and a binding on another node requeues nothing.
func TestServiceVIPBinding_NodePeerRequests(t *testing.T) {
	a := newConflictBinding("a", testConflictVIPA, testConflictBackendA, 20)
	b := newConflictBinding("b", testConflictVIPB, testConflictBackendB, 10)
	other := newConflictBinding("other", testConflictVIPB, testConflictBackendB, 10)
	other.Spec.TargetRef.Name = "some-other-node"
	r, _ := newConflictReconciler(t, &fakeVIPTable{}, a, b, other)

	reqs := r.nodePeerRequests(context.Background(), a)
	if len(reqs) != 1 || reqs[0].Name != "b" {
		t.Errorf("nodePeerRequests(a) = %v, want [b]", reqs)
	}
	if reqs := r.nodePeerRequests(context.Background(), other); len(reqs) != 0 {
		t.Errorf("nodePeerRequests(other) = %v, want none", reqs)
	}
}

func conflictKey(name string) types.NamespacedName {
	return types.NamespacedName{Namespace: testNamespace, Name: name}
}

// TestServiceVIPBinding_DeletingTwinKeepsRows: deleting one of two bindings
// with identical values leaves the rows, which the other binding writes too.
func TestServiceVIPBinding_DeletingTwinKeepsRows(t *testing.T) {
	old := newConflictBinding(testConflictOld, testConflictVIPA, testConflictBackendA, 20)
	twin := newConflictBinding(testConflictYoung, testConflictVIPA, testConflictBackendA, 10)
	table := &fakeVIPTable{}
	r, c := newConflictReconciler(t, table, old, twin)
	reconcileBinding(t, r, testConflictOld)
	reconcileBinding(t, r, testConflictYoung)

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := c.Get(context.Background(), conflictKey(testConflictOld), got); err != nil {
		t.Fatalf("get old: %v", err)
	}
	if err := c.Delete(context.Background(), got); err != nil {
		t.Fatalf("delete old: %v", err)
	}
	reconcileBinding(t, r, testConflictOld)

	if len(table.unregBinding) != 0 || len(table.unregAt) != 0 {
		t.Errorf("unregBinding=%d unregAt=%d, want 0: the twin still needs the rows",
			len(table.unregBinding), len(table.unregAt))
	}
	if _, ok := table.rows[ingressRow(testConflictVIPA)]; !ok {
		t.Errorf("VIP A ingress row is gone after deleting one of two identical bindings")
	}
	if _, ok := table.rows[egressRow(testConflictBackendA)]; !ok {
		t.Errorf("backend A egress row is gone after deleting one of two identical bindings")
	}
}

// assertRowRewrite fails t unless the simulated row at k rewrites to want.
func assertRowRewrite(t *testing.T, table *fakeVIPTable, k fakeRowKey, want, what string) {
	t.Helper()
	if got := table.rows[k].addr; got != net.ParseIP(want).String() {
		t.Errorf("%s rewrites to %q, want %q", what, got, want)
	}
}
