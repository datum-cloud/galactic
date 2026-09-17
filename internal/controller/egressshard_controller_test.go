// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net/netip"
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
	testNAT66Namespace = "galactic-system"
	testNAT66NodeA     = "node-a"
	testNAT66NodeB     = "node-b"
	testNAT66ShardName = "node-a"
	testNAT66ShardAddr = "2001:db8:9999::1"

	// A well-formed uFMT 48+16 uSID: Block fc00:0001:0002, Node-ID 9,
	// Function 0xE (uEnd.DT46), Argument 0x001. The shape matters now that the
	// advertisement is the SID's covering locator rather than a host route --
	// testNAT66ShardSIDLocator is what that advertisement must carry, and the
	// Function and Argument nibbles below it are exactly what must be masked
	// off. The configured Argument is a placeholder every real deployment also
	// sets; installEgressRoutes overwrites it per tenant.
	testNAT66ShardSIDVal     = "fc00:1:2:9:e001::"
	testNAT66ShardSIDLocator = "fc00:1:2:9::/64"
)

// fakeDatapath is an EgressDatapath test double. It echoes whatever address it
// is programmed with, the way the real datapath's identity reports the row it
// just wrote, and records every call so a test can assert that a shard
// targeting another node is never programmed at all.
type fakeDatapath struct {
	attached bool

	// programErr, when set, fails every Program call, standing in for a map
	// write the kernel rejected.
	programErr error

	// calls records each address passed to Program, in order. An invalid entry
	// is a reconcile that found no assigned address in spec.
	calls []netip.Addr

	// programmed is the address this datapath currently holds, mirroring the
	// real one's refusal to ever clear a row.
	programmed netip.Addr
}

func (f *fakeDatapath) Attached() bool { return f.attached }

func (f *fakeDatapath) Program(addressIPv6 netip.Addr) (EgressShardIdentity, error) {
	f.calls = append(f.calls, addressIPv6)
	if f.programErr != nil {
		return f.identity(), f.programErr
	}
	if addressIPv6.IsValid() {
		f.programmed = addressIPv6
	}
	return f.identity(), nil
}

func (f *fakeDatapath) identity() EgressShardIdentity {
	if !f.programmed.IsValid() {
		return EgressShardIdentity{}
	}
	return EgressShardIdentity{ShardAddressIPv6: f.programmed.String()}
}

func nat66TestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
	return scheme
}

// newEgressShard builds the fixture EgressShard object (always named
// testNAT66ShardName, matching every reconcileReq call below) targeting
// nodeName.
func newEgressShard(nodeName string) *bgpv1alpha1.EgressShard {
	return &bgpv1alpha1.EgressShard{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNAT66Namespace, Name: testNAT66ShardName},
		Spec: bgpv1alpha1.EgressShardSpec{
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
	sid      string
	datapath EgressDatapath

	// health, when non-nil, receives every SetProgrammedHealth call, so a test
	// can assert what a readiness probe would have seen.
	health *[]bool
}

func newNAT66Reconciler(p nat66ReconcilerParams) *EgressShardReconciler {
	r := &EgressShardReconciler{
		Client:   p.client,
		Scheme:   p.scheme,
		NodeName: p.nodeName,
		ShardSID: p.sid,
		Datapath: p.datapath,
	}
	if p.health != nil {
		r.SetProgrammedHealth = func(programmed bool) { *p.health = append(*p.health, programmed) }
	}
	return r
}

// newAssignedEgressShard builds the fixture EgressShard whose spec assigns it
// an IPv6 masquerade address, which is where that address now comes from.
func newAssignedEgressShard(nodeName string) *bgpv1alpha1.EgressShard {
	shard := newEgressShard(nodeName)
	shard.Spec.ShardAddressIPv6 = testNAT66ShardAddr
	return shard
}

func reconcileReq(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: client.ObjectKey{Namespace: testNAT66Namespace, Name: name}}
}

func TestEgressShardReconciler_NotFoundIsANoop(t *testing.T) {
	scheme := nat66TestScheme(t)
	c := newIndexedClientBuilder(scheme).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq("does-not-exist")); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil for a NotFound object", err)
	}
}

func TestEgressShardReconciler_SkipsShardForAnotherNode(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeB)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddressIPv6 != "" {
		t.Errorf("Status.ShardAddressIPv6 = %q, want untouched empty string (shard targets another node)",
			got.Status.ShardAddressIPv6)
	}
	if len(got.Status.Conditions) != 0 {
		t.Errorf("Status.Conditions = %+v, want untouched empty slice (shard targets another node)",
			got.Status.Conditions)
	}
}

func TestEgressShardReconciler_PublishesStatusWhenAttached(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddressIPv6 != testNAT66ShardAddr {
		t.Errorf("Status.ShardAddressIPv6 = %q, want %q", got.Status.ShardAddressIPv6, testNAT66ShardAddr)
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
	if cond.Reason != reasonEgressDatapathAttached {
		t.Errorf("Ready condition reason = %q, want %q", cond.Reason, reasonEgressDatapathAttached)
	}
}

func TestEgressShardReconciler_ReadyFalseWhenNotAttached(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: false},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.EgressShard{}
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
	if cond.Reason != reasonEgressDatapathNotAttached {
		t.Errorf("Ready condition reason = %q, want %q", cond.Reason, reasonEgressDatapathNotAttached)
	}
}

func TestEgressShardReconciler_NilDatapathIsNotAttached(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: nil,
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.EgressShard{}
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

func TestEgressShardReconciler_DeletingShardIsANoop(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	shard.Finalizers = []string{"test.datum.net/keep"} // required for the fake client to accept a deletion timestamp
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()

	if err := c.Delete(context.Background(), shard); err != nil {
		t.Fatalf("delete shard: %v", err)
	}

	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: true},
	})
	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddressIPv6 != "" {
		t.Errorf("Status.ShardAddressIPv6 = %q, want untouched empty string for a terminating shard",
			got.Status.ShardAddressIPv6)
	}
}

func TestEgressShardReconciler_EmptyConfiguredValuesLeaveStatusUntouched(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	shard.Status.ShardAddressIPv6 = testNAT66ShardAddr
	shard.Status.ShardSID = testNAT66ShardSIDVal
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()

	// A reconciler started with empty ShardAddress/ShardSID (shouldn't
	// happen in production -- config.NAT66Config.Validate requires both --
	// but must not clobber a previously-published value with an empty
	// string if it somehow does).
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: "", datapath: &fakeDatapath{attached: true},
	})
	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddressIPv6 != testNAT66ShardAddr {
		t.Errorf("Status.ShardAddressIPv6 = %q, want untouched %q", got.Status.ShardAddressIPv6, testNAT66ShardAddr)
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
// reconciles against testNAT66NodeA, so unlike newEgressShard/
// newNAT66Reconciler (which do vary their own node-related argument
// across tests, e.g. TestEgressShardReconciler_SkipsShardForAnotherNode),
// this takes no arguments at all.
func newTestNAT66Router() *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNAT66Namespace, Name: testNAT66RouterName},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: testNAT66NodeA}},
	}
}

// TestEgressShardReconciler_CreatesAdvertisementForBothSIDAndAddress covers
// the 2026-08-19 fix: the shard's advertisement must carry ShardAddress
// (the return leg -- see shardAdvertisementPrefixes' own doc comment) as
// well as ShardSID (the forward leg), not just the latter -- a real TCP
// connection through NAT66 never completed while only ShardSID was
// advertised, since no route back to ShardAddress existed anywhere else
// on the fabric.
func TestEgressShardReconciler_CreatesAdvertisementForBothSIDAndAddress(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeA)
	router := newTestNAT66Router()
	c := newIndexedClientBuilder(scheme).WithObjects(shard, router).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: true},
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
		bgpv1alpha1.Prefix(testNAT66ShardSIDLocator),
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

// TestShardAdvertisementPrefixes_AdvertisesTheSIDsCoveringLocator is the
// control-plane half of #538. A tenant VRF's egress route encapsulates toward
// this shard with that tenant's own Argument written into the SID, so the
// destination differs per tenant and the operator-configured /128 covers
// exactly one of them -- the rest resolve through whatever covering aggregate
// the underlay happens to carry, or not at all. Advertising the whole locator
// is what makes every tenant's destination reachable, and it is the same
// 64-bit "is this mine" granularity locator_matches already applies at the
// shard.
//
// It also asserts the mask: Function and Argument must not survive into the
// advertised prefix, or two shards differing only below bit 64 would advertise
// overlapping-but-unequal prefixes.
func TestShardAdvertisementPrefixes_AdvertisesTheSIDsCoveringLocator(t *testing.T) {
	shard := &bgpv1alpha1.EgressShard{}
	shard.Status.ShardSID = testNAT66ShardSIDVal

	got, err := shardAdvertisementPrefixes(shard)
	if err != nil {
		t.Fatalf("shardAdvertisementPrefixes() error = %v, want nil", err)
	}
	if len(got) != 1 || string(got[0]) != testNAT66ShardSIDLocator {
		t.Errorf("shardAdvertisementPrefixes() = %+v, want [%s]", got, testNAT66ShardSIDLocator)
	}
}

// TestShardAdvertisementPrefixes_SameLocatorWhateverTheConfiguredArgument
// states the property the previous test's mask exists for: two operators
// picking different placeholder Argument values for the same shard must not
// produce two different advertisements.
func TestShardAdvertisementPrefixes_SameLocatorWhateverTheConfiguredArgument(t *testing.T) {
	sids := []string{"fc00:1:2:9:e001::", "fc00:1:2:9:efff::", "fc00:1:2:9::"}
	prefixes := make([]string, 0, len(sids))
	for _, sid := range sids {
		shard := &bgpv1alpha1.EgressShard{}
		shard.Status.ShardSID = sid

		got, err := shardAdvertisementPrefixes(shard)
		if err != nil {
			t.Fatalf("shardAdvertisementPrefixes(%q) error = %v, want nil", sid, err)
		}
		prefixes = append(prefixes, string(got[0]))
	}
	for _, got := range prefixes {
		if got != testNAT66ShardSIDLocator {
			t.Errorf("shardAdvertisementPrefixes() = %v, want every entry to be %s", prefixes, testNAT66ShardSIDLocator)
		}
	}
}

// TestShardAdvertisementPrefixes_RejectsANonIPv6SID guards the /64: an IPv4
// ShardSID has no 64-bit locator to advertise, and silently emitting something
// else would put a bogus prefix into the EVPN mesh.
func TestShardAdvertisementPrefixes_RejectsANonIPv6SID(t *testing.T) {
	shard := &bgpv1alpha1.EgressShard{}
	shard.Status.ShardSID = "192.0.2.1"

	if _, err := shardAdvertisementPrefixes(shard); err == nil {
		t.Error("shardAdvertisementPrefixes() error = nil, want an error for an IPv4 shard SID")
	}
}

// TestShardAdvertisementPrefixes_ShardAddressStaysAHostRoute is the other side
// of the /64 change: the masquerade source address is an ordinary address, not
// a uSID, nothing varies below it, and widening it would attract traffic this
// shard has no business receiving.
func TestShardAdvertisementPrefixes_ShardAddressStaysAHostRoute(t *testing.T) {
	shard := &bgpv1alpha1.EgressShard{}
	shard.Status.ShardAddressIPv6 = testNAT66ShardAddr

	got, err := shardAdvertisementPrefixes(shard)
	if err != nil {
		t.Fatalf("shardAdvertisementPrefixes() error = %v, want nil", err)
	}
	want := testNAT66ShardAddr + "/128"
	if len(got) != 1 || string(got[0]) != want {
		t.Errorf("shardAdvertisementPrefixes() = %+v, want [%s]", got, want)
	}
}

// TestEgressShardReconciler_AdvertisesShardAddressAloneWhenSIDUnset covers
// shardAdvertisementPrefixes' "either may be independently unset" claim
// from the other direction: with no ShardSID configured at all (an
// operator mid-rollout, or a shard that only participates in the return
// leg), ShardAddress alone must still be advertised -- the old
// implementation's `if shard.Status.ShardSID == "" { return nil }` guard
// would have skipped this entirely.
func TestEgressShardReconciler_AdvertisesShardAddressAloneWhenSIDUnset(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeA)
	router := newTestNAT66Router()
	c := newIndexedClientBuilder(scheme).WithObjects(shard, router).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: "", datapath: &fakeDatapath{attached: true},
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

// TestEgressShardReconciler_SkipsAdvertisementWhenNeitherSIDNorAddressSet
// covers shardAdvertisementPrefixes' all-empty case: no advertisement at
// all, not an error, when an operator hasn't configured either value yet.
func TestEgressShardReconciler_SkipsAdvertisementWhenNeitherSIDNorAddressSet(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	router := newTestNAT66Router()
	c := newIndexedClientBuilder(scheme).WithObjects(shard, router).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: "", datapath: &fakeDatapath{attached: true},
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

func TestEgressShardReconciler_SkipsAdvertisementWithoutRouter(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: true},
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

func TestEgressShardReconciler_WithdrawsAdvertisementOnDelete(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
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
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: true},
	})
	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.BGPAdvertisement{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(adv), got); err == nil {
		t.Fatalf("BGPAdvertisement %v still exists after deleting its EgressShard", client.ObjectKeyFromObject(adv))
	}
}

func TestEgressShardReconciler_WithdrawsAdvertisementWhenShardObjectAlreadyGone(t *testing.T) {
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
		sid: testNAT66ShardSIDVal, datapath: &fakeDatapath{attached: true},
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil for a NotFound shard object", err)
	}

	got := &bgpv1alpha1.BGPAdvertisement{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(adv), got); err == nil {
		t.Fatalf("BGPAdvertisement %v still exists after its EgressShard object disappeared", client.ObjectKeyFromObject(adv))
	}
}

// TestEgressShardReconciler_ProgramsTheAssignedAddress is the core of the move
// from process configuration to spec: the address a controller assigns must
// reach the datapath, and status must report the address the datapath was
// programmed with rather than the one the spec asked for.
func TestEgressShardReconciler_ProgramsTheAssignedAddress(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	datapath := &fakeDatapath{attached: true}
	var health []bool
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: datapath, health: &health,
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	if len(datapath.calls) != 1 || datapath.calls[0].String() != testNAT66ShardAddr {
		t.Fatalf("Program calls = %v, want one call with %s", datapath.calls, testNAT66ShardAddr)
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddressIPv6 != testNAT66ShardAddr {
		t.Errorf("Status.ShardAddressIPv6 = %q, want %q", got.Status.ShardAddressIPv6, testNAT66ShardAddr)
	}

	cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeProgrammed)
	if cond == nil {
		t.Fatal("Programmed condition not set")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("Programmed condition status = %v, want True", cond.Status)
	}
	if cond.Reason != bgpv1alpha1.ProgrammedReasonAddressesProgrammed {
		t.Errorf("Programmed condition reason = %q, want %q",
			cond.Reason, bgpv1alpha1.ProgrammedReasonAddressesProgrammed)
	}
	if len(health) != 1 || !health[0] {
		t.Errorf("SetProgrammedHealth calls = %v, want [true]", health)
	}
}

// TestEgressShardReconciler_AttachedButUnassignedIsNotProgrammed covers the
// state startup now passes through, and can sit in indefinitely: the XDP
// program is attached and claims no packet, because no controller has assigned
// this shard an address. Ready says attached, which it is. Programmed is what
// says the shard translates nothing, and the health signal a readiness probe
// reads follows Programmed rather than attachment.
func TestEgressShardReconciler_AttachedButUnassignedIsNotProgrammed(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	datapath := &fakeDatapath{attached: true}
	var health []bool
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: datapath, health: &health,
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddressIPv6 != "" {
		t.Errorf("Status.ShardAddressIPv6 = %q, want empty for an unassigned shard", got.Status.ShardAddressIPv6)
	}

	ready := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Errorf("Ready condition = %+v, want True (the datapath is attached)", ready)
	}

	cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeProgrammed)
	if cond == nil {
		t.Fatal("Programmed condition not set")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("Programmed condition status = %v, want False", cond.Status)
	}
	if cond.Reason != bgpv1alpha1.ProgrammedReasonAddressUnassigned {
		t.Errorf("Programmed condition reason = %q, want %q",
			cond.Reason, bgpv1alpha1.ProgrammedReasonAddressUnassigned)
	}
	if len(health) != 1 || health[0] {
		t.Errorf("SetProgrammedHealth calls = %v, want [false]", health)
	}
}

// TestEgressShardReconciler_ProgrammingFailureIsReportedAndRetried pins both
// halves of a failed map write: it lands on the object as
// Programmed=ProgrammingFailed, and it comes back out of Reconcile so the
// controller retries it.
func TestEgressShardReconciler_ProgrammingFailureIsReportedAndRetried(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	datapath := &fakeDatapath{attached: true, programErr: errors.New("map is full")}
	var health []bool
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: datapath, health: &health,
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err == nil {
		t.Fatal("Reconcile() error = nil, want the programming failure returned for retry")
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeProgrammed)
	if cond == nil {
		t.Fatal("Programmed condition not set")
	}
	if cond.Reason != bgpv1alpha1.ProgrammedReasonProgrammingFailed {
		t.Errorf("Programmed condition reason = %q, want %q",
			cond.Reason, bgpv1alpha1.ProgrammedReasonProgrammingFailed)
	}
	if len(health) != 1 || health[0] {
		t.Errorf("SetProgrammedHealth calls = %v, want [false]", health)
	}
}

// TestEgressShardReconciler_NilDatapathReportsProgrammingFailedWithoutRetrying
// is the one programming failure that must not come back out of Reconcile: no
// retry can conjure a datapath into a process that failed to load one.
func TestEgressShardReconciler_NilDatapathReportsProgrammingFailedWithoutRetrying(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: nil,
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil for a failure no retry can fix", err)
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, bgpv1alpha1.ConditionTypeProgrammed)
	if cond == nil || cond.Reason != bgpv1alpha1.ProgrammedReasonProgrammingFailed {
		t.Errorf("Programmed condition = %+v, want reason %q", cond, bgpv1alpha1.ProgrammedReasonProgrammingFailed)
	}
}

// TestEgressShardReconciler_NeverProgramsAnotherNodesShard is the node check
// seen from the datapath's side. Every node's process watches every EgressShard
// in the namespace, so a shard assigned an address for a different node must
// not reach this node's map -- which would make two nodes translate with one
// address and deliver each other's replies.
func TestEgressShardReconciler_NeverProgramsAnotherNodesShard(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeB)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	datapath := &fakeDatapath{attached: true}
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: datapath,
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(datapath.calls) != 0 {
		t.Errorf("Program calls = %v, want none for a shard targeting another node", datapath.calls)
	}
}

// TestEgressShardReconciler_StatusFollowsTheDatapathNotTheSpec states which of
// the two the status fields answer to. A datapath that programmed one address
// and is then handed another keeps translating with the first until the write
// lands, so status must report what the datapath says it holds, not what spec
// assigns.
func TestEgressShardReconciler_StatusFollowsTheDatapathNotTheSpec(t *testing.T) {
	const programmedAddr = "2001:db8:9999::7"

	scheme := nat66TestScheme(t)
	shard := newAssignedEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	datapath := &fakeDatapath{
		attached:   true,
		programErr: errors.New("map is full"),
		programmed: netip.MustParseAddr(programmedAddr),
	}
	r := newNAT66Reconciler(nat66ReconcilerParams{
		client: c, scheme: scheme, nodeName: testNAT66NodeA,
		sid: testNAT66ShardSIDVal, datapath: datapath,
	})

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err == nil {
		t.Fatal("Reconcile() error = nil, want the programming failure returned for retry")
	}

	got := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(shard), got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	if got.Status.ShardAddressIPv6 != programmedAddr {
		t.Errorf("Status.ShardAddressIPv6 = %q, want the programmed %q rather than the assigned %q",
			got.Status.ShardAddressIPv6, programmedAddr, testNAT66ShardAddr)
	}
}
