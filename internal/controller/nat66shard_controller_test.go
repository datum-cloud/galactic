// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testNAT66Namespace   = "galactic-system"
	testNAT66NodeA       = "node-a"
	testNAT66NodeB       = "node-b"
	testNAT66ShardName   = "node-a"
	testNAT66ShardAddr   = "2001:db8:9999::1"
	testNAT66ShardSIDVal = "fc00:1:2::1"
)

// fakeDatapathHealth is a NAT66DatapathHealth test double whose Attached
// return value is directly settable.
type fakeDatapathHealth struct {
	attached bool
}

func (f *fakeDatapathHealth) Attached() bool { return f.attached }

func nat66TestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
	return scheme
}

// newNAT66Shard builds the fixture NAT66Shard object (always named
// testNAT66ShardName, matching every reconcileReq call below) targeting
// nodeName.
func newNAT66Shard(nodeName string) *bgpv1alpha1.NAT66Shard {
	return &bgpv1alpha1.NAT66Shard{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNAT66Namespace, Name: testNAT66ShardName},
		Spec: bgpv1alpha1.NAT66ShardSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: nodeName},
		},
	}
}

// nat66ReconcilerParams bundles newNAT66Reconciler's arguments so the
// per-test call sites don't overflow the line-length limit.
type nat66ReconcilerParams struct {
	client   client.Client
	scheme   *runtime.Scheme
	nodeName string
	addr     string
	sid      string
	datapath NAT66DatapathHealth
}

func newNAT66Reconciler(p nat66ReconcilerParams) *NAT66ShardReconciler {
	return &NAT66ShardReconciler{
		Client:       p.client,
		Scheme:       p.scheme,
		NodeName:     p.nodeName,
		ShardAddress: p.addr,
		ShardSID:     p.sid,
		Datapath:     p.datapath,
	}
}

func reconcileReq(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: client.ObjectKey{Namespace: testNAT66Namespace, Name: name}}
}

func TestNAT66ShardReconciler_NotFoundIsANoop(t *testing.T) {
	scheme := nat66TestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: &fakeDatapathHealth{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq("does-not-exist")); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil for a NotFound object", err)
	}
}

func TestNAT66ShardReconciler_SkipsShardForAnotherNode(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeB)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: &fakeDatapathHealth{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.NAT66Shard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddress != "" {
		t.Errorf("Status.ShardAddress = %q, want untouched empty string (shard targets another node)",
			got.Status.ShardAddress)
	}
	if len(got.Status.Conditions) != 0 {
		t.Errorf("Status.Conditions = %+v, want untouched empty slice (shard targets another node)",
			got.Status.Conditions)
	}
}

func TestNAT66ShardReconciler_PublishesStatusWhenAttached(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: &fakeDatapathHealth{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.NAT66Shard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddress != testNAT66ShardAddr {
		t.Errorf("Status.ShardAddress = %q, want %q", got.Status.ShardAddress, testNAT66ShardAddr)
	}
	if got.Status.ShardSID != testNAT66ShardSIDVal {
		t.Errorf("Status.ShardSID = %q, want %q", got.Status.ShardSID, testNAT66ShardSIDVal)
	}
	if got.Status.ObservedGeneration != shard.Generation {
		t.Errorf("Status.ObservedGeneration = %d, want %d", got.Status.ObservedGeneration, shard.Generation)
	}

	cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
	if cond == nil {
		t.Fatal("Ready condition not set")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("Ready condition status = %v, want True", cond.Status)
	}
	if cond.Reason != reasonNAT66DatapathAttached {
		t.Errorf("Ready condition reason = %q, want %q", cond.Reason, reasonNAT66DatapathAttached)
	}
}

func TestNAT66ShardReconciler_ReadyFalseWhenNotAttached(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: &fakeDatapathHealth{attached: false},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.NAT66Shard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}

	cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
	if cond == nil {
		t.Fatal("Ready condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("Ready condition status = %v, want False", cond.Status)
	}
	if cond.Reason != reasonNAT66DatapathNotAttached {
		t.Errorf("Ready condition reason = %q, want %q", cond.Reason, reasonNAT66DatapathNotAttached)
	}
}

func TestNAT66ShardReconciler_NilDatapathIsNotAttached(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: nil,
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.NAT66Shard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
	if cond == nil {
		t.Fatal("Ready condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("Ready condition status = %v, want False for a nil Datapath", cond.Status)
	}
}

func TestNAT66ShardReconciler_DeletingShardIsANoop(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	shard.Finalizers = []string{"test.datum.net/keep"} // required for the fake client to accept a deletion timestamp
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()

	if err := c.Delete(context.Background(), shard); err != nil {
		t.Fatalf("delete shard: %v", err)
	}

	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: &fakeDatapathHealth{attached: true},
	})
	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.NAT66Shard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddress != "" {
		t.Errorf("Status.ShardAddress = %q, want untouched empty string for a terminating shard", got.Status.ShardAddress)
	}
}

func TestNAT66ShardReconciler_EmptyConfiguredValuesLeaveStatusUntouched(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	shard.Status.ShardAddress = testNAT66ShardAddr
	shard.Status.ShardSID = testNAT66ShardSIDVal
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()

	// A reconciler started with empty ShardAddress/ShardSID (shouldn't
	// happen in production -- config.NAT66Config.Validate requires both --
	// but must not clobber a previously-published value with an empty
	// string if it somehow does).
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: "", sid: "", datapath: &fakeDatapathHealth{attached: true},
	})
	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.NAT66Shard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddress != testNAT66ShardAddr {
		t.Errorf("Status.ShardAddress = %q, want untouched %q", got.Status.ShardAddress, testNAT66ShardAddr)
	}
	if got.Status.ShardSID != testNAT66ShardSIDVal {
		t.Errorf("Status.ShardSID = %q, want untouched %q", got.Status.ShardSID, testNAT66ShardSIDVal)
	}
}
