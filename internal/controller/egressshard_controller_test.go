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
	c := newIndexedClientBuilder(scheme).Build()
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
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
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
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
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
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
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
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
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
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()

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
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()

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

// testNAT66RouterName is the deterministic name every newTestNAT66Router
// fixture below uses -- no test needs a second, differently-named
// BGPRouter, so this is a plain constant rather than a parameter.
const testNAT66RouterName = "node-a-router"

// newTestNAT66Router returns a BGPRouter named testNAT66RouterName,
// targeting testNAT66NodeA, resolved through the BGPRouterByTargetName
// index newIndexedClientBuilder (shared with
// networkgateway_controller_test.go) registers. Every call site below
// reconciles against testNAT66NodeA, so unlike newNAT66Shard/
// newNAT66Reconciler (which do vary their own node-related argument
// across tests, e.g. TestNAT66ShardReconciler_SkipsShardForAnotherNode),
// this takes no arguments at all.
func newTestNAT66Router() *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNAT66Namespace, Name: testNAT66RouterName},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: testNAT66NodeA}},
	}
}

// TestNAT66ShardReconciler_CreatesAdvertisementForBothSIDAndAddress covers
// the 2026-08-19 fix: the shard's advertisement must carry ShardAddress
// (the return leg -- see shardAdvertisementPrefixes' own doc comment) as
// well as ShardSID (the forward leg), not just the latter -- a real TCP
// connection through NAT66 never completed while only ShardSID was
// advertised, since no route back to ShardAddress existed anywhere else
// on the fabric.
func TestNAT66ShardReconciler_CreatesAdvertisementForBothSIDAndAddress(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	router := newTestNAT66Router()
	c := newIndexedClientBuilder(scheme).WithObjects(shard, router).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: &fakeDatapathHealth{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	advKey := client.ObjectKey{Namespace: testNAT66Namespace, Name: shardAdvertisementName(testNAT66ShardName)}
	if err := c.Get(context.Background(), advKey, adv); err != nil {
		t.Fatalf("get shard BGPAdvertisement: %v", err)
	}
	if adv.Spec.RouterRef.Name != router.Name {
		t.Errorf("Spec.RouterRef.Name = %q, want %q", adv.Spec.RouterRef.Name, router.Name)
	}
	if adv.Spec.AddressFamily.AFI != bgpv1alpha1.AFIL2VPN || adv.Spec.AddressFamily.SAFI != bgpv1alpha1.SAFIEVPN {
		t.Errorf("Spec.AddressFamily = %+v, want l2vpn/evpn", adv.Spec.AddressFamily)
	}
	wantPrefixes := []bgpv1alpha1.Prefix{
		bgpv1alpha1.Prefix(testNAT66ShardSIDVal + "/128"),
		bgpv1alpha1.Prefix(testNAT66ShardAddr + "/128"),
	}
	if len(adv.Spec.Prefixes) != len(wantPrefixes) {
		t.Fatalf("Spec.Prefixes = %+v, want %+v", adv.Spec.Prefixes, wantPrefixes)
	}
	for i, want := range wantPrefixes {
		if adv.Spec.Prefixes[i] != want {
			t.Errorf("Spec.Prefixes[%d] = %s, want %s", i, adv.Spec.Prefixes[i], want)
		}
	}
}

// TestNAT66ShardReconciler_AdvertisesShardAddressAloneWhenSIDUnset covers
// shardAdvertisementPrefixes' "either may be independently unset" claim
// from the other direction: with no ShardSID configured at all (an
// operator mid-rollout, or a shard that only participates in the return
// leg), ShardAddress alone must still be advertised -- the old
// implementation's `if shard.Status.ShardSID == "" { return nil }` guard
// would have skipped this entirely.
func TestNAT66ShardReconciler_AdvertisesShardAddressAloneWhenSIDUnset(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	router := newTestNAT66Router()
	c := newIndexedClientBuilder(scheme).WithObjects(shard, router).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: "", datapath: &fakeDatapathHealth{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	advKey := client.ObjectKey{Namespace: testNAT66Namespace, Name: shardAdvertisementName(testNAT66ShardName)}
	if err := c.Get(context.Background(), advKey, adv); err != nil {
		t.Fatalf("get shard BGPAdvertisement: %v", err)
	}
	wantPrefix := bgpv1alpha1.Prefix(testNAT66ShardAddr + "/128")
	if len(adv.Spec.Prefixes) != 1 || adv.Spec.Prefixes[0] != wantPrefix {
		t.Errorf("Spec.Prefixes = %+v, want [%s]", adv.Spec.Prefixes, wantPrefix)
	}
}

// TestNAT66ShardReconciler_SkipsAdvertisementWhenNeitherSIDNorAddressSet
// covers shardAdvertisementPrefixes' all-empty case: no advertisement at
// all, not an error, when an operator hasn't configured either value yet.
func TestNAT66ShardReconciler_SkipsAdvertisementWhenNeitherSIDNorAddressSet(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	router := newTestNAT66Router()
	c := newIndexedClientBuilder(scheme).WithObjects(shard, router).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: "", sid: "", datapath: &fakeDatapathHealth{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	advKey := client.ObjectKey{Namespace: testNAT66Namespace, Name: shardAdvertisementName(testNAT66ShardName)}
	if err := c.Get(context.Background(), advKey, adv); err == nil {
		t.Fatalf("BGPAdvertisement %v unexpectedly created with neither ShardSID nor ShardAddress configured", advKey)
	}
}

func TestNAT66ShardReconciler_SkipsAdvertisementWithoutRouter(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: &fakeDatapathHealth{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil even with no BGPRouter for this node yet", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	advKey := client.ObjectKey{Namespace: testNAT66Namespace, Name: shardAdvertisementName(testNAT66ShardName)}
	if err := c.Get(context.Background(), advKey, adv); err == nil {
		t.Fatalf("BGPAdvertisement %v unexpectedly created with no BGPRouter for this node", advKey)
	}
}

func TestNAT66ShardReconciler_WithdrawsAdvertisementOnDelete(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newNAT66Shard(testNAT66NodeA)
	shard.Finalizers = []string{"test.datum.net/keep"} // required for the fake client to accept a deletion timestamp
	router := newTestNAT66Router()
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNAT66Namespace,
			Name:      shardAdvertisementName(testNAT66ShardName),
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: router.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(testNAT66ShardSIDVal + "/128")},
		},
	}
	c := newIndexedClientBuilder(scheme).WithObjects(shard, router, adv).WithStatusSubresource(shard).Build()

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

	got := &bgpv1alpha1.BGPAdvertisement{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(adv), got); err == nil {
		t.Fatalf("BGPAdvertisement %v still exists after deleting its NAT66Shard", client.ObjectKeyFromObject(adv))
	}
}

func TestNAT66ShardReconciler_WithdrawsAdvertisementWhenShardObjectAlreadyGone(t *testing.T) {
	// Mirrors NetworkGatewayReconciler's own req.Name-keyed withdrawal in
	// its NotFound branch: this reconciler never observes a live shard
	// object at all here, only the deletion event's req.Name, and must
	// still withdraw the advertisement it created (see the Reconcile
	// NotFound branch's own doc comment for why no finalizer is used).
	scheme := nat66TestScheme(t)
	router := newTestNAT66Router()
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNAT66Namespace,
			Name:      shardAdvertisementName(testNAT66ShardName),
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: router.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(testNAT66ShardSIDVal + "/128")},
		},
	}
	c := newIndexedClientBuilder(scheme).WithObjects(router, adv).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		addr: testNAT66ShardAddr, sid: testNAT66ShardSIDVal, datapath: &fakeDatapathHealth{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil for a NotFound shard object", err)
	}

	got := &bgpv1alpha1.BGPAdvertisement{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(adv), got); err == nil {
		t.Fatalf("BGPAdvertisement %v still exists after its NAT66Shard object disappeared", client.ObjectKeyFromObject(adv))
	}
}
