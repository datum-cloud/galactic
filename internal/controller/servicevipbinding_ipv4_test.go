// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// newIPv4TapBinding returns a tap binding of the IPv4 VIP testVIP4:8080 to
// the IPv6 backend testBackendAddr:30080, which newBackendFixtures'
// advertisement covers.
func newIPv4TapBinding() *bgpv1alpha1.ServiceVIPBinding {
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.VIPAddress = testVIP4
	binding.Spec.BackendAddress = testBackendAddr
	return binding
}

// reconcileIPv4Binding reconciles binding against a real VipXlatTable over an
// in-memory map and returns the client.
func reconcileIPv4Binding(
	t *testing.T, binding *bgpv1alpha1.ServiceVIPBinding, table *vipxlatmap.VipXlatTable,
) client.Client {
	t.Helper()
	router, adv, vrf := newBackendFixtures(testVPCRef)
	fakeClient := fake.NewClientBuilder().
		WithScheme(newRuleTestScheme(t)).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	return fakeClient
}

// TestServiceVIPBindingReconciler_ProgramsIPv4VIPTranslation: an IPv4 VIP's
// binding to an IPv6 backend lands as an ingress row keyed on the IPv4-mapped
// VIP under the slot the gateway derives from the IPv6 backend, rewriting to
// the backend, and an egress-translated row keyed on the backend, rewriting to
// the IPv4-mapped VIP. The binding reports Bound, and deleting it removes both
// rows.
func TestServiceVIPBindingReconciler_ProgramsIPv4VIPTranslation(t *testing.T) {
	mem := newMemTable()
	table := vipxlatmap.NewVipXlatTable(mem)
	c := reconcileIPv4Binding(t, newIPv4TapBinding(), table)

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := c.Get(context.Background(), bindingKey(), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound) {
		t.Fatalf("Bound condition = %+v, want True", got.Status.Conditions)
	}

	vip := netip.MustParseAddr("::ffff:" + testVIP4).As16()
	backend := netip.MustParseAddr(testBackendAddr).As16()
	wantSlot := srv6.BackendSlot(netip.MustParseAddr(testBackendAddr), 30080)
	if len(mem.entries) != 2 {
		t.Fatalf("map holds %d rows, want 2", len(mem.entries))
	}
	for k, v := range mem.entries {
		key, value := k.(prog.UsidVipXlatKey), v.(prog.UsidVipXlatValue)
		switch vipxlatmap.Direction(key.Direction) {
		case vipxlatmap.DirectionIngress:
			if key.Addr != vip || value.Addr != backend || key.Slot != wantSlot {
				t.Errorf("ingress row key %x slot %#04x -> %x, want %x slot %#04x -> %x",
					key.Addr, key.Slot, value.Addr, vip, wantSlot, backend)
			}
		case vipxlatmap.DirectionEgressTranslated:
			if key.Addr != backend || value.Addr != vip || key.Slot != 0 {
				t.Errorf("egress-translated row key %x slot %#04x -> %x, want %x slot 0 -> %x",
					key.Addr, key.Slot, value.Addr, backend, vip)
			}
		default:
			t.Errorf("unexpected %s row", vipxlatmap.Direction(key.Direction))
		}
	}

	controllerutil.AddFinalizer(got, serviceVIPBindingFinalizer)
	now := metav1.Now()
	got.DeletionTimestamp = &now
	got.ResourceVersion = ""
	reconcileIPv4Binding(t, got, table)
	if len(mem.entries) != 0 {
		t.Errorf("map holds %d rows after delete, want 0", len(mem.entries))
	}
}

// TestServiceVIPBindingReconciler_RefusesIPv4Backend: a binding with an IPv4
// backendAddress, whatever its VIP's family, is reported BindFailed and writes
// nothing, and deleting it completes without touching the map.
func TestServiceVIPBindingReconciler_RefusesIPv4Backend(t *testing.T) {
	for name, vip := range map[string]string{"IPv4VIP": testVIP4, "IPv6VIP": testVIPBindingVIPAddr} {
		t.Run(name, func(t *testing.T) {
			mem := newMemTable()
			table := vipxlatmap.NewVipXlatTable(mem)
			binding := newIPv4TapBinding()
			binding.Spec.VIPAddress, binding.Spec.BackendAddress = vip, testBackendAddr4

			router, adv, vrf := newBackendFixtures(testVPCRef)
			c := fake.NewClientBuilder().
				WithScheme(newRuleTestScheme(t)).
				WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
				WithObjects(router, adv, vrf, binding).
				Build()
			r := &ServiceVIPBindingReconciler{Client: c, NodeName: testComputeNodeName, VIPTranslationTable: table}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err == nil {
				t.Fatal("Reconcile: want an error for an IPv4 backend")
			}
			got := &bgpv1alpha1.ServiceVIPBinding{}
			if err := c.Get(context.Background(), bindingKey(), got); err != nil {
				t.Fatalf("get: %v", err)
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound)
			if cond == nil || cond.Status != metav1.ConditionFalse || !strings.Contains(cond.Message, "is IPv4") {
				t.Errorf("Bound = %+v, want False naming the IPv4 backend", cond)
			}
			if len(mem.entries) != 0 {
				t.Errorf("map holds %d rows, want 0", len(mem.entries))
			}

			now := metav1.Now()
			got.DeletionTimestamp = &now
			if err := c.Delete(context.Background(), got); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
				t.Fatalf("Reconcile delete: %v", err)
			}
			if err := c.Get(context.Background(), bindingKey(), got); !apierrors.IsNotFound(err) {
				t.Errorf("get after delete: err = %v, want NotFound", err)
			}
		})
	}
}

// translatedEgressRow is the egress-translated row a conflict-test binding of
// an IPv4 VIP to backend claims.
func translatedEgressRow(backend string) fakeRowKey {
	k := egressRow(backend)
	k.translated = true
	return k
}

// TestServiceVIPBinding_IPv4AndIPv6VIPsShareBackendSocket: an IPv4 VIP's and
// an IPv6 VIP's bindings to one backend socket both bind, each with its own
// ingress row and its own egress row, apart by direction.
func TestServiceVIPBinding_IPv4AndIPv6VIPsShareBackendSocket(t *testing.T) {
	v6 := newConflictBinding("v6", testConflictVIPA, testConflictBackendA, 20)
	v4 := newConflictBinding("v4", testVIP4, testConflictBackendA, 10)
	table := &fakeVIPTable{}
	r, c := newConflictReconciler(t, table, v6, v4)

	reconcileBinding(t, r, "v6")
	reconcileBinding(t, r, "v4")

	for _, name := range []string{"v6", "v4"} {
		if cond := boundCondition(t, c, name); cond == nil || cond.Status != metav1.ConditionTrue {
			t.Errorf("binding %s Bound = %+v, want True", name, cond)
		}
	}
	backend := net.ParseIP(testConflictBackendA).String()
	want := map[fakeRowKey]string{
		ingressRow(testConflictVIPA, testConflictBackendA): backend,
		ingressRow(testVIP4, testConflictBackendA):         backend,
		egressRow(testConflictBackendA):                    net.ParseIP(testConflictVIPA).String(),
		translatedEgressRow(testConflictBackendA):          testVIP4,
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

// TestServiceVIPBinding_TwoIPv4VIPsOnOneBackendSocketConflict: two IPv4 VIPs'
// bindings to one backend socket claim the same egress-translated row, so the
// older binds and the younger reports Conflict and writes nothing.
func TestServiceVIPBinding_TwoIPv4VIPsOnOneBackendSocketConflict(t *testing.T) {
	const otherVIP4 = "203.0.113.6"
	old := newConflictBinding(testConflictOld, testVIP4, testConflictBackendA, 20)
	young := newConflictBinding(testConflictYoung, otherVIP4, testConflictBackendA, 10)
	table := &fakeVIPTable{}
	r, c := newConflictReconciler(t, table, old, young)

	reconcileBinding(t, r, testConflictYoung)
	reconcileBinding(t, r, testConflictOld)

	if cond := boundCondition(t, c, testConflictOld); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("older binding Bound = %+v, want True", cond)
	}
	cond := boundCondition(t, c, testConflictYoung)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonVIPRowConflict ||
		!strings.Contains(cond.Message, "egress-translated row") {
		t.Errorf("younger binding Bound = %+v, want False/Conflict naming the egress-translated row", cond)
	}
	if got := table.rows[translatedEgressRow(testConflictBackendA)].addr; got != testVIP4 {
		t.Errorf("egress-translated row rewrites to %q, want the older VIP %s", got, testVIP4)
	}
	if _, ok := table.rows[ingressRow(otherVIP4, testConflictBackendA)]; ok {
		t.Error("the younger binding wrote its ingress row; want neither of its rows")
	}
}

// TestXlatAddresses covers the address forms the controller hands vipxlatmap:
// a VIP in 4 bytes for IPv4, plain or IPv4-mapped in the spec, and 16 for
// IPv6, always beside a 16-byte IPv6 backend, and nothing for an IPv4 backend
// or an unparseable address.
func TestXlatAddresses(t *testing.T) {
	for _, tc := range []struct {
		name, vip, backend string
		wantVIPLen         int
	}{
		{"IPv6VIP", testVIPBindingVIPAddr, testBackendAddr, net.IPv6len},
		{"IPv4VIP", testVIP4, testBackendAddr, net.IPv4len},
		{"IPv4MappedVIP", "::ffff:" + testVIP4, testBackendAddr, net.IPv4len},
		{"IPv4Backend", testVIP4, testBackendAddr4, 0},
		{"IPv4MappedBackend", testVIP4, "::ffff:" + testBackendAddr4, 0},
		{"Unparseable", testVIP4, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newIPv4TapBinding()
			b.Spec.VIPAddress, b.Spec.BackendAddress = tc.vip, tc.backend
			vip, backend, ok := xlatAddresses(b)
			if ok != (tc.wantVIPLen != 0) {
				t.Fatalf("ok = %v, want %v", ok, tc.wantVIPLen != 0)
			}
			if ok && (len(vip) != tc.wantVIPLen || len(backend) != net.IPv6len) {
				t.Errorf("lengths = %d, %d, want %d, %d", len(vip), len(backend), tc.wantVIPLen, net.IPv6len)
			}
		})
	}
}
