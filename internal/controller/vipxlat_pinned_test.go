// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
)

type countingCloser struct{ closed int }

func (c *countingCloser) Close() error {
	c.closed++
	return nil
}

// TestServiceVIPBindingReconciler_TapBindsOncePinAppears covers a node that has
// just booted: galactic-router starts before galactic-cni pins vip_xlat_table,
// so a tap-kind binding fails at first. Once the pin exists, the next reconcile
// opens it and binds without a restart, and later reconciles reuse the handle.
func TestServiceVIPBindingReconciler_TapBindsOncePinAppears(t *testing.T) {
	scheme := newRuleTestScheme(t)
	router, adv, vrf := newBackendFixtures(testVPCRef)
	binding := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, testComputeNodeName)
	binding.Spec.BackendAddress = testBackendAddr
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(router, adv, vrf, binding).
		Build()

	errNoPin := errors.New("open pinned map: no such file or directory")
	mem := newMemTable()
	closer := &countingCloser{}
	pinned, opens := false, 0
	table := &PinnedVIPTranslationTable{Open: func() (*vipxlatmap.VipXlatTable, io.Closer, error) {
		opens++
		if !pinned {
			return nil, nil, errNoPin
		}
		return vipxlatmap.NewVipXlatTable(mem), closer, nil
	}}
	r := &ServiceVIPBindingReconciler{Client: fakeClient, NodeName: testComputeNodeName, VIPTranslationTable: table}
	req := ctrl.Request{NamespacedName: bindingKey()}

	if _, err := r.Reconcile(context.Background(), req); !errors.Is(err, errNoPin) {
		t.Fatalf("Reconcile before the pin exists: err = %v, want it to wrap %v", err, errNoPin)
	}

	pinned = true
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile after the pin appears: %v", err)
	}
	entries, err := vipxlatmap.NewVipXlatTable(mem).List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("vip_xlat_table holds %d rows, want the binding's ingress and egress rows", len(entries))
	}
	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := fakeClient.Get(context.Background(), bindingKey(), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, bgpv1alpha1.ConditionTypeBound) {
		t.Errorf("Bound condition = %+v, want True", got.Status.Conditions)
	}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile again: %v", err)
	}
	if opens != 2 {
		t.Errorf("Open called %d times, want 2: one failed, then one kept for every later call", opens)
	}

	if err := table.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if closer.closed != 1 {
		t.Errorf("handle closed %d times, want 1", closer.closed)
	}
}

// TestPinnedVIPTranslationTable_CloseBeforeOpen: closing a table whose pin never
// opened succeeds.
func TestPinnedVIPTranslationTable_CloseBeforeOpen(t *testing.T) {
	table := &PinnedVIPTranslationTable{Open: func() (*vipxlatmap.VipXlatTable, io.Closer, error) {
		return nil, nil, errors.New("no pin")
	}}
	if _, err := table.Table(); err == nil {
		t.Fatal("Table: want an error while the pin is missing")
	}
	if err := table.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestPinnedVIPTranslationTable_NoReopenAfterClose: a call that lands after
// Close, such as a GC tick racing shutdown, fails instead of opening a handle
// nothing would close, and a second Close closes nothing more.
func TestPinnedVIPTranslationTable_NoReopenAfterClose(t *testing.T) {
	closer := &countingCloser{}
	opens := 0
	table := &PinnedVIPTranslationTable{Open: func() (*vipxlatmap.VipXlatTable, io.Closer, error) {
		opens++
		return vipxlatmap.NewVipXlatTable(newMemTable()), closer, nil
	}}
	if _, err := table.Table(); err != nil {
		t.Fatalf("Table: %v", err)
	}
	if err := table.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := table.Table(); !errors.Is(err, errVIPTranslationTableClosed) {
		t.Errorf("Table after Close: err = %v, want %v", err, errVIPTranslationTableClosed)
	}
	if err := table.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if opens != 1 || closer.closed != 1 {
		t.Errorf("opens = %d, closes = %d, want 1 each", opens, closer.closed)
	}
}

// TestPinnedVIPTranslationTable_ConcurrentFirstUse: reconciles and the sweep
// asking for the table at once open the pin once and share one handle.
func TestPinnedVIPTranslationTable_ConcurrentFirstUse(t *testing.T) {
	var opens atomic.Int32
	table := &PinnedVIPTranslationTable{Open: func() (*vipxlatmap.VipXlatTable, io.Closer, error) {
		opens.Add(1)
		return vipxlatmap.NewVipXlatTable(newMemTable()), &countingCloser{}, nil
	}}
	const callers = 16
	got := make([]*vipxlatmap.VipXlatTable, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tbl, err := table.Table()
			if err != nil {
				t.Errorf("Table: %v", err)
			}
			got[i] = tbl
		}()
	}
	wg.Wait()
	if n := opens.Load(); n != 1 {
		t.Errorf("Open called %d times, want 1", n)
	}
	for i := 1; i < callers; i++ {
		if got[i] != got[0] {
			t.Fatalf("caller %d got a different handle", i)
		}
	}
}
