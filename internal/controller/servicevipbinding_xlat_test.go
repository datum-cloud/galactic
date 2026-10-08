// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// testIPv6BackendPrefix is an advertised prefix containing
// testVIPBindingBackendAddr, so an IPv6 binding's VRF context resolves.
const testIPv6BackendPrefix = "fd20:60::/64"

// memTable is an in-memory usidmap.Table, so these tests drive the real
// vipxlatmap ownership checks rather than a call-recording fake.
type memTable struct {
	entries map[any]any
	order   []any
}

func newMemTable() *memTable { return &memTable{entries: make(map[any]any)} }

func (m *memTable) Put(key, value any) error {
	if _, ok := m.entries[key]; !ok {
		m.order = append(m.order, key)
	}
	m.entries[key] = value
	return nil
}

func (m *memTable) Lookup(key, valueOut any) error {
	v, ok := m.entries[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(v))
	return nil
}

func (m *memTable) Delete(key any) error {
	if _, ok := m.entries[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, key)
	for i, k := range m.order {
		if k == key {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return nil
}

func (m *memTable) Iterate() usidmap.Iterator { return &memIterator{table: m, idx: -1} }

type memIterator struct {
	table *memTable
	idx   int
}

func (it *memIterator) Next(keyOut, valueOut any) bool {
	it.idx++
	if it.idx >= len(it.table.order) {
		return false
	}
	k := it.table.order[it.idx]
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(k))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.table.entries[k]))
	return true
}

func (it *memIterator) Err() error { return nil }

// deleteBindingWithVRFPresent registers rows for each backend in backends at
// the binding's resolved VRF, all behind the test VIP and ports, then deletes
// the binding whose backend is testVIPBindingBackendAddr while its VRF is
// still on the node. It returns the table for inspection.
func deleteBindingWithVRFPresent(t *testing.T, backends ...string) *vipxlatmap.VipXlatTable {
	t.Helper()
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	adv.Spec.Prefixes = append(adv.Spec.Prefixes, testIPv6BackendPrefix)
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	controllerutil.AddFinalizer(binding, serviceVIPBindingFinalizer)
	now := metav1.Now()
	binding.DeletionTimestamp = &now

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	block, argument, err := resolveVIPBindingContext(context.Background(), fakeClient, testNamespace,
		testComputeNodeName, netip.MustParseAddr(testVIPBindingBackendAddr))
	if err != nil {
		t.Fatalf("resolveVIPBindingContext: %v", err)
	}

	table := vipxlatmap.NewVipXlatTable(newMemTable())
	vip := net.ParseIP(testVIPBindingVIPAddr)
	for _, b := range backends {
		backend := net.ParseIP(b)
		slot := srv6.BackendSlot(netip.MustParseAddr(b), 30080)
		if err := table.RegisterIngress(block, argument, slot, ipProtoTCP, vip, 8080, backend, 30080); err != nil {
			t.Fatalf("RegisterIngress: %v", err)
		}
		if err := table.RegisterEgress(block, argument, ipProtoTCP, backend, 30080, vip, 8080); err != nil {
			t.Fatalf("RegisterEgress: %v", err)
		}
	}

	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: bindingKey()}); err != nil {
		t.Fatalf("Reconcile: unexpected error: %v", err)
	}
	err = fakeClient.Get(context.Background(), bindingKey(), &bgpv1alpha1.ServiceVIPBinding{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get: got err=%v, want NotFound (finalizer removal should let deletion complete)", err)
	}
	return table
}

func TestServiceVIPBindingReconciler_DeleteWithVRFRemovesOwnRows(t *testing.T) {
	table := deleteBindingWithVRFPresent(t, testVIPBindingBackendAddr)

	entries, err := table.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("table holds %+v after delete, want no rows", entries)
	}
}

// TestServiceVIPBindingReconciler_DeleteWithVRFKeepsSharedRows covers two
// backends of one rule on this node behind the same VIP and port, where the
// second one's ingress row overwrote the first's. Deleting the first while its
// VRF is still present removes only its own egress row and leaves both of the
// second's rows.
func TestServiceVIPBindingReconciler_DeleteWithVRFKeepsSharedRows(t *testing.T) {
	const otherBackend = "fd20:60::6:6"
	table := deleteBindingWithVRFPresent(t, testVIPBindingBackendAddr, otherBackend)

	entries, err := table.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("table holds %d rows after delete, want 2 (the other binding's)", len(entries))
	}
	for _, e := range entries {
		if e.Direction == vipxlatmap.DirectionIngress && !e.RewriteAddr.Equal(net.ParseIP(otherBackend)) {
			t.Errorf("ingress row rewrites to %s, want the other binding's backend %s", e.RewriteAddr, otherBackend)
		}
	}
}
