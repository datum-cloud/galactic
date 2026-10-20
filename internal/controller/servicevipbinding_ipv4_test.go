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

// newIPv4TapBinding returns a tap binding of testVIP4:8080 to
// testBackendAddr4:30080, which newBackendFixtures' advertisement covers.
func newIPv4TapBinding() *bgpv1alpha1.ServiceVIPBinding {
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.VIPAddress = testVIP4
	binding.Spec.BackendAddress = testBackendAddr4
	return binding
}

// reconcileIPv4Binding reconciles binding against a real VipXlatTable over an
// in-memory map and returns the client and the map.
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

// TestServiceVIPBindingReconciler_ProgramsIPv4BindingInMappedForm: an IPv4
// binding's two rows land in vip_xlat_table with IPv4-mapped addresses, the
// ingress row under the slot the gateway derives from the IPv4 backend, and
// the binding reports Bound. Deleting it removes both rows.
func TestServiceVIPBindingReconciler_ProgramsIPv4BindingInMappedForm(t *testing.T) {
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
	backend := netip.MustParseAddr("::ffff:" + testBackendAddr4).As16()
	wantSlot := srv6.BackendSlot(netip.MustParseAddr(testBackendAddr4), 30080)
	if len(mem.entries) != 2 {
		t.Fatalf("map holds %d rows, want 2", len(mem.entries))
	}
	for k, v := range mem.entries {
		key, value := k.(prog.UsidVipXlatKey), v.(prog.UsidVipXlatValue)
		switch key.Direction {
		case uint8(vipxlatmap.DirectionIngress):
			if key.Addr != vip || value.Addr != backend || key.Slot != wantSlot {
				t.Errorf("ingress row key %x slot %#04x -> %x, want %x slot %#04x -> %x",
					key.Addr, key.Slot, value.Addr, vip, wantSlot, backend)
			}
		case uint8(vipxlatmap.DirectionEgress):
			if key.Addr != backend || value.Addr != vip || key.Slot != 0 {
				t.Errorf("egress row key %x slot %#04x -> %x, want %x slot 0 -> %x",
					key.Addr, key.Slot, value.Addr, backend, vip)
			}
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

// TestServiceVIPBindingReconciler_RefusesMixedFamilyBinding: a binding whose
// VIP and backend are of different families is reported BindFailed and writes
// nothing, and deleting it completes without touching the map.
func TestServiceVIPBindingReconciler_RefusesMixedFamilyBinding(t *testing.T) {
	for name, tc := range map[string]struct{ vip, backend string }{
		"IPv4VIPIPv6Backend": {testVIP4, testBackendAddr},
		"IPv6VIPIPv4Backend": {testVIPBindingVIPAddr, testBackendAddr4},
	} {
		t.Run(name, func(t *testing.T) {
			mem := newMemTable()
			table := vipxlatmap.NewVipXlatTable(mem)
			binding := newIPv4TapBinding()
			binding.Spec.VIPAddress, binding.Spec.BackendAddress = tc.vip, tc.backend

			router, adv, vrf := newBackendFixtures(testVPCRef)
			c := fake.NewClientBuilder().
				WithScheme(newRuleTestScheme(t)).
				WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
				WithObjects(router, adv, vrf, binding).
				Build()
			r := &ServiceVIPBindingReconciler{Client: c, NodeName: testComputeNodeName, VIPTranslationTable: table}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err == nil {
				t.Fatal("Reconcile: want an error for a mixed-family binding")
			}
			got := &bgpv1alpha1.ServiceVIPBinding{}
			if err := c.Get(context.Background(), bindingKey(), got); err != nil {
				t.Fatalf("get: %v", err)
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound)
			if cond == nil || cond.Status != metav1.ConditionFalse || !strings.Contains(cond.Message, "address family") {
				t.Errorf("Bound = %+v, want False naming the address families", cond)
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

// TestXlatAddresses covers the address forms the controller hands vipxlatmap:
// 4 bytes for IPv4, plain or IPv4-mapped in the spec, 16 for IPv6, and nothing
// for a mixed or unparseable pair.
func TestXlatAddresses(t *testing.T) {
	for _, tc := range []struct {
		name, vip, backend string
		wantLen            int
	}{
		{"BothIPv6", testVIPBindingVIPAddr, testBackendAddr, net.IPv6len},
		{"BothIPv4", testVIP4, testBackendAddr4, net.IPv4len},
		{"IPv4Mapped", "::ffff:" + testVIP4, testBackendAddr4, net.IPv4len},
		{"Mixed", testVIP4, testBackendAddr, 0},
		{"Unparseable", testVIP4, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newIPv4TapBinding()
			b.Spec.VIPAddress, b.Spec.BackendAddress = tc.vip, tc.backend
			vip, backend, ok := xlatAddresses(b)
			if ok != (tc.wantLen != 0) {
				t.Fatalf("ok = %v, want %v", ok, tc.wantLen != 0)
			}
			if ok && (len(vip) != tc.wantLen || len(backend) != tc.wantLen) {
				t.Errorf("lengths = %d, %d, want %d", len(vip), len(backend), tc.wantLen)
			}
		})
	}
}
