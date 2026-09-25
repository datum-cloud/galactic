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
	testNAT64ShardAddr = "192.0.2.10"
	testNAT64Prefix    = "2001:db8:64::/96"

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

// fakeEgressDatapath is an EgressDatapath test double holding its programmed
// identity in memory, with settable attachment and Program failure.
type fakeEgressDatapath struct {
	attached   bool
	programErr error

	identity *EgressShardIdentity
	programs int
	clears   int
}

func (f *fakeEgressDatapath) Attached() bool { return f.attached }

func (f *fakeEgressDatapath) Program(identity EgressShardIdentity) error {
	f.programs++
	if f.programErr != nil {
		return f.programErr
	}
	f.identity = &identity
	return nil
}

func (f *fakeEgressDatapath) Clear() error {
	f.clears++
	f.identity = nil
	return nil
}

func (f *fakeEgressDatapath) Programmed() (EgressShardIdentity, bool) {
	if f.identity == nil {
		return EgressShardIdentity{}, false
	}
	return *f.identity, true
}

func nat66TestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(bgpv1alpha1.AddToScheme(scheme))
	return scheme
}

// newEgressShard builds the fixture EgressShard object (always named
// testNAT66ShardName, matching every reconcileReq call below) targeting
// nodeName, with a NAT66 identity assigned in its spec.
func newEgressShard(nodeName string) *bgpv1alpha1.EgressShard {
	return &bgpv1alpha1.EgressShard{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNAT66Namespace, Name: testNAT66ShardName},
		Spec: bgpv1alpha1.EgressShardSpec{
			TargetRef:        bgpv1alpha1.TargetRef{Kind: "Node", Name: nodeName},
			ShardSID:         testNAT66ShardSIDVal,
			ShardAddressIPv6: testNAT66ShardAddr,
		},
	}
}

func newNAT66Reconciler(c client.Client, scheme *runtime.Scheme, datapath EgressDatapath) *EgressShardReconciler {
	return &EgressShardReconciler{
		Client:   c,
		Scheme:   scheme,
		NodeName: testNAT66NodeA,
		Datapath: datapath,
	}
}

func reconcileReq(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: client.ObjectKey{Namespace: testNAT66Namespace, Name: name}}
}

// reconcileShard reconciles testNAT66ShardName and returns the shard as stored
// afterwards.
func reconcileShard(t *testing.T, r *EgressShardReconciler, c client.Client) (*bgpv1alpha1.EgressShard, error) {
	t.Helper()
	_, reconcileErr := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName))
	got := &bgpv1alpha1.EgressShard{}
	key := client.ObjectKey{Namespace: testNAT66Namespace, Name: testNAT66ShardName}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get shard after reconcile: %v", err)
	}
	return got, reconcileErr
}

func assertCondition(t *testing.T, shard *bgpv1alpha1.EgressShard, condType string,
	wantStatus metav1.ConditionStatus, wantReason string,
) {
	t.Helper()
	cond := meta.FindStatusCondition(shard.Status.Conditions, condType)
	if cond == nil {
		t.Fatalf("%s condition not set", condType)
	}
	if cond.Status != wantStatus || cond.Reason != wantReason {
		t.Errorf("%s condition = %v/%q, want %v/%q", condType, cond.Status, cond.Reason, wantStatus, wantReason)
	}
}

func TestEgressShardReconciler_NotFoundClearsTheDatapath(t *testing.T) {
	scheme := nat66TestScheme(t)
	c := newIndexedClientBuilder(scheme).Build()
	datapath := &fakeEgressDatapath{attached: true, identity: &EgressShardIdentity{}}
	r := newNAT66Reconciler(c, scheme, datapath)

	if _, err := r.Reconcile(context.Background(), reconcileReq("does-not-exist")); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil for a NotFound object", err)
	}
	// No shard targets this node, so an identity inherited from a previous
	// process's pinned map must not survive.
	if _, ok := datapath.Programmed(); ok {
		t.Error("datapath still programmed with no EgressShard targeting this node")
	}
}

func TestEgressShardReconciler_SkipsShardForAnotherNode(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeB)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	datapath := &fakeEgressDatapath{attached: true}
	r := newNAT66Reconciler(c, scheme, datapath)

	got, err := reconcileShard(t, r, c)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if datapath.programs != 0 {
		t.Errorf("datapath programmed %d times from a shard targeting another node", datapath.programs)
	}
	if got.Status.ShardAddressIPv6 != "" || len(got.Status.Conditions) != 0 {
		t.Errorf("Status = %+v, want untouched (shard targets another node)", got.Status)
	}
}

func TestEgressShardReconciler_ProgramsDatapathFromSpec(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	shard.Spec.ShardAddressIPv4 = testNAT64ShardAddr
	shard.Spec.NAT64Prefix = testNAT64Prefix
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	datapath := &fakeEgressDatapath{attached: true}
	r := newNAT66Reconciler(c, scheme, datapath)

	got, err := reconcileShard(t, r, c)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	want := EgressShardIdentity{
		ShardSID:         netip.MustParseAddr(testNAT66ShardSIDVal),
		ShardAddressIPv6: netip.MustParseAddr(testNAT66ShardAddr),
		ShardAddressIPv4: netip.MustParseAddr(testNAT64ShardAddr),
		NAT64Prefix:      netip.MustParsePrefix(testNAT64Prefix),
	}
	if identity, ok := datapath.Programmed(); !ok || identity != want {
		t.Errorf("datapath identity = %+v (programmed %v), want %+v", identity, ok, want)
	}

	if got.Status.ShardSID != testNAT66ShardSIDVal {
		t.Errorf("Status.ShardSID = %q, want %q", got.Status.ShardSID, testNAT66ShardSIDVal)
	}
	if got.Status.ShardAddressIPv6 != testNAT66ShardAddr {
		t.Errorf("Status.ShardAddressIPv6 = %q, want %q", got.Status.ShardAddressIPv6, testNAT66ShardAddr)
	}
	if got.Status.ShardAddressIPv4 != testNAT64ShardAddr {
		t.Errorf("Status.ShardAddressIPv4 = %q, want %q", got.Status.ShardAddressIPv4, testNAT64ShardAddr)
	}
	if got.Status.NAT64Prefix != testNAT64Prefix {
		t.Errorf("Status.NAT64Prefix = %q, want %q", got.Status.NAT64Prefix, testNAT64Prefix)
	}
	if got.Status.ObservedGeneration != shard.Generation {
		t.Errorf("Status.ObservedGeneration = %d, want %d", got.Status.ObservedGeneration, shard.Generation)
	}
	assertCondition(t, got, bgpv1alpha1.ConditionTypeReady, metav1.ConditionTrue, reasonEgressDatapathAttached)
	assertCondition(t, got, bgpv1alpha1.ConditionTypeProgrammed, metav1.ConditionTrue,
		bgpv1alpha1.ProgrammedReasonAddressesProgrammed)
}

func TestEgressShardReconciler_ReadyFalseWhenNotAttached(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(c, scheme, &fakeEgressDatapath{attached: false})

	got, err := reconcileShard(t, r, c)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	assertCondition(t, got, bgpv1alpha1.ConditionTypeReady, metav1.ConditionFalse, reasonEgressDatapathNotAttached)
}

func TestEgressShardReconciler_NilDatapathIsAnError(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(c, scheme, nil)

	if _, err := reconcileShard(t, r, c); err == nil {
		t.Fatal("Reconcile() error = nil, want an error with no datapath to program")
	}
}

// TestEgressShardReconciler_UnassignedIdentityClearsTheDatapath covers a shard
// whose spec does not yet assign enough to translate with. It exists from the
// moment its node is labelled and gains an identity afterwards, so this is a
// normal state rather than an error, and the datapath must not keep one the
// spec does not assign.
func TestEgressShardReconciler_UnassignedIdentityClearsTheDatapath(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*bgpv1alpha1.EgressShardSpec)
	}{
		{name: "no SID", mutate: func(s *bgpv1alpha1.EgressShardSpec) { s.ShardSID = "" }},
		{name: "no address for either family", mutate: func(s *bgpv1alpha1.EgressShardSpec) { s.ShardAddressIPv6 = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := nat66TestScheme(t)
			shard := newEgressShard(testNAT66NodeA)
			tt.mutate(&shard.Spec)
			c := newIndexedClientBuilder(scheme).WithObjects(shard, newTestNAT66Router()).
				WithStatusSubresource(shard).Build()
			datapath := &fakeEgressDatapath{attached: true, identity: &EgressShardIdentity{}}
			r := newNAT66Reconciler(c, scheme, datapath)

			got, err := reconcileShard(t, r, c)
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if _, ok := datapath.Programmed(); ok || datapath.programs != 0 {
				t.Errorf("datapath programmed from a spec with no usable identity")
			}
			if got.Status.ShardSID != "" || got.Status.ShardAddressIPv6 != "" {
				t.Errorf("Status = %+v, want no identity published", got.Status)
			}
			assertCondition(t, got, bgpv1alpha1.ConditionTypeProgrammed, metav1.ConditionFalse,
				bgpv1alpha1.ProgrammedReasonAddressUnassigned)
			assertNoAdvertisement(t, c)
		})
	}
}

// TestEgressShardReconciler_StatusReportsTheDatapathNotTheSpec covers the
// status contract: when programming fails, status must keep reporting what
// the datapath still translates with, not the spec it failed to apply.
func TestEgressShardReconciler_StatusReportsTheDatapathNotTheSpec(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	previous := EgressShardIdentity{
		ShardSID:         netip.MustParseAddr("fc00:1:2:8::"),
		ShardAddressIPv6: netip.MustParseAddr("2001:db8:8888::1"),
	}
	datapath := &fakeEgressDatapath{attached: true, identity: &previous, programErr: errors.New("map write failed")}
	r := newNAT66Reconciler(c, scheme, datapath)

	got, err := reconcileShard(t, r, c)
	if err == nil {
		t.Fatal("Reconcile() error = nil, want the programming failure returned for a retry")
	}
	if got.Status.ShardAddressIPv6 != "2001:db8:8888::1" {
		t.Errorf("Status.ShardAddressIPv6 = %q, want the still-programmed %q", got.Status.ShardAddressIPv6,
			"2001:db8:8888::1")
	}
	assertCondition(t, got, bgpv1alpha1.ConditionTypeProgrammed, metav1.ConditionFalse,
		bgpv1alpha1.ProgrammedReasonProgrammingFailed)
}

// TestEgressShardReconciler_ConflictingShardsProgramNone covers two
// EgressShards targeting one node. The datapath holds one identity, and
// picking one would make which shard translates depend on list order.
func TestEgressShardReconciler_ConflictingShardsProgramNone(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	other := newEgressShard(testNAT66NodeA)
	other.Name = "node-a-duplicate"
	other.Spec.ShardSID = "fc00:1:2:a::"
	c := newIndexedClientBuilder(scheme).WithObjects(shard, other, newTestNAT66Router()).
		WithStatusSubresource(shard, other).Build()
	datapath := &fakeEgressDatapath{attached: true}
	r := newNAT66Reconciler(c, scheme, datapath)

	got, err := reconcileShard(t, r, c)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, ok := datapath.Programmed(); ok || datapath.programs != 0 {
		t.Error("datapath programmed while two EgressShards target this node")
	}

	gotOther := &bgpv1alpha1.EgressShard{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(other), gotOther); err != nil {
		t.Fatalf("get other shard: %v", err)
	}
	for _, s := range []*bgpv1alpha1.EgressShard{got, gotOther} {
		assertCondition(t, s, bgpv1alpha1.ConditionTypeProgrammed, metav1.ConditionFalse, reasonEgressShardConflict)
		if s.Status.ShardSID != "" {
			t.Errorf("%s Status.ShardSID = %q, want none published while in conflict", s.Name, s.Status.ShardSID)
		}
	}
	assertNoAdvertisement(t, c)
}

func TestEgressShardReconciler_TerminatingShardClearsTheDatapath(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	shard.Finalizers = []string{"test.datum.net/keep"} // required for the fake client to accept a deletion timestamp
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	if err := c.Delete(context.Background(), shard); err != nil {
		t.Fatalf("delete shard: %v", err)
	}
	datapath := &fakeEgressDatapath{attached: true, identity: &EgressShardIdentity{}}
	r := newNAT66Reconciler(c, scheme, datapath)

	got, err := reconcileShard(t, r, c)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, ok := datapath.Programmed(); ok {
		t.Error("datapath still programmed for a terminating EgressShard")
	}
	if got.Status.ShardAddressIPv6 != "" {
		t.Errorf("Status.ShardAddressIPv6 = %q, want untouched empty string for a terminating shard",
			got.Status.ShardAddressIPv6)
	}
}

// assertNoAdvertisement fails if testNAT66ShardName's BGPAdvertisement exists.
func assertNoAdvertisement(t *testing.T, c client.Client) {
	t.Helper()
	adv := &bgpv1alpha1.BGPAdvertisement{}
	advKey := client.ObjectKey{Namespace: testNAT66Namespace, Name: shardAdvertisementName(testNAT66ShardName)}
	if err := c.Get(context.Background(), advKey, adv); err == nil {
		t.Errorf("BGPAdvertisement %v exists, want none", advKey)
	}
}

// testNAT66RouterName is the deterministic name every newTestNAT66Router
// fixture below uses -- no test needs a second, differently-named
// BGPRouter, so this is a plain constant rather than a parameter.
const testNAT66RouterName = "node-a-router"

// newTestNAT66Router returns a BGPRouter named testNAT66RouterName,
// targeting testNAT66NodeA, resolved through the BGPRouterByTargetName
// index newIndexedClientBuilder (shared with
// networkgateway_controller_test.go) registers. Every reconciler here runs
// as testNAT66NodeA, so this takes no arguments at all.
func newTestNAT66Router() *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNAT66Namespace, Name: testNAT66RouterName},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: testNAT66NodeA}},
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

// TestEgressShardReconciler_CreatesAdvertisementForBothSIDAndAddress covers
// the 2026-08-19 fix: the shard's advertisement must carry the IPv6 shard
// address (the return leg -- see shardAdvertisementPrefixes' own doc comment)
// as well as the SID (the forward leg), not just the latter -- a real TCP
// connection through NAT66 never completed while only the SID was advertised,
// since no route back to the address existed anywhere else on the fabric.
func TestEgressShardReconciler_CreatesAdvertisementForBothSIDAndAddress(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	router := newTestNAT66Router()
	c := newIndexedClientBuilder(scheme).WithObjects(shard, router).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(c, scheme, &fakeEgressDatapath{attached: true})

	if _, err := reconcileShard(t, r, c); err != nil {
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

// TestEgressShardReconciler_NAT64OnlyShardAdvertisesTheSIDAlone covers
// shardAdvertisementPrefixes' "either may be independently unset" claim: a
// shard serving only NAT64 has no IPv6 masquerade address, and its SID must
// still be advertised. The IPv4 address never is -- see
// shardAdvertisementPrefixes' doc comment.
func TestEgressShardReconciler_NAT64OnlyShardAdvertisesTheSIDAlone(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	shard.Spec.ShardAddressIPv6 = ""
	shard.Spec.ShardAddressIPv4 = testNAT64ShardAddr
	shard.Spec.NAT64Prefix = testNAT64Prefix
	c := newIndexedClientBuilder(scheme).WithObjects(shard, newTestNAT66Router()).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(c, scheme, &fakeEgressDatapath{attached: true})

	if _, err := reconcileShard(t, r, c); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{}
	advKey := client.ObjectKey{Namespace: testNAT66Namespace, Name: shardAdvertisementName(testNAT66ShardName)}
	if err := c.Get(context.Background(), advKey, adv); err != nil {
		t.Fatalf("get shard BGPAdvertisement: %v", err)
	}
	wantPrefix := bgpv1alpha1.Prefix(testNAT66ShardSIDLocator)
	if len(adv.Spec.Prefixes) != 1 || adv.Spec.Prefixes[0] != wantPrefix {
		t.Errorf("Spec.Prefixes = %+v, want [%s]", adv.Spec.Prefixes, wantPrefix)
	}
}

// TestEgressShardReconciler_WithdrawsStaleAdvertisementWhenUnprogrammed
// covers the advertisement following status: a shard its node no longer
// translates for must not keep attracting traffic to that node.
func TestEgressShardReconciler_WithdrawsStaleAdvertisementWhenUnprogrammed(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	shard.Spec.ShardSID = ""
	c := newIndexedClientBuilder(scheme).WithObjects(shard, newTestNAT66Router(), staleShardAdvertisement()).
		WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(c, scheme, &fakeEgressDatapath{attached: true})

	if _, err := reconcileShard(t, r, c); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	assertNoAdvertisement(t, c)
}

func TestEgressShardReconciler_SkipsAdvertisementWithoutRouter(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	c := newIndexedClientBuilder(scheme).WithObjects(shard).WithStatusSubresource(shard).Build()
	r := newNAT66Reconciler(c, scheme, &fakeEgressDatapath{attached: true})

	if _, err := reconcileShard(t, r, c); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil even with no BGPRouter for this node yet", err)
	}
	assertNoAdvertisement(t, c)
}

// staleShardAdvertisement is the BGPAdvertisement a previous reconcile of
// testNAT66ShardName left behind.
func staleShardAdvertisement() *bgpv1alpha1.BGPAdvertisement {
	return &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNAT66Namespace,
			Name:      shardAdvertisementName(testNAT66ShardName),
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: testNAT66RouterName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(testNAT66ShardSIDLocator)},
		},
	}
}

func TestEgressShardReconciler_WithdrawsAdvertisementOnDelete(t *testing.T) {
	scheme := nat66TestScheme(t)
	shard := newEgressShard(testNAT66NodeA)
	shard.Finalizers = []string{"test.datum.net/keep"} // required for the fake client to accept a deletion timestamp
	c := newIndexedClientBuilder(scheme).WithObjects(shard, newTestNAT66Router(), staleShardAdvertisement()).
		WithStatusSubresource(shard).Build()
	if err := c.Delete(context.Background(), shard); err != nil {
		t.Fatalf("delete shard: %v", err)
	}
	r := newNAT66Reconciler(c, scheme, &fakeEgressDatapath{attached: true})

	if _, err := reconcileShard(t, r, c); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	assertNoAdvertisement(t, c)
}

func TestEgressShardReconciler_WithdrawsAdvertisementWhenShardObjectAlreadyGone(t *testing.T) {
	// Mirrors NetworkGatewayReconciler's own req.Name-keyed withdrawal in
	// its NotFound branch: this reconciler never observes a live shard
	// object at all here, only the deletion event's req.Name, and must
	// still withdraw the advertisement it created and stop translating
	// (see the Reconcile NotFound branch's own doc comment for why no
	// finalizer is used).
	scheme := nat66TestScheme(t)
	c := newIndexedClientBuilder(scheme).WithObjects(newTestNAT66Router(), staleShardAdvertisement()).Build()
	datapath := &fakeEgressDatapath{attached: true, identity: &EgressShardIdentity{}}
	r := newNAT66Reconciler(c, scheme, datapath)

	if _, err := r.Reconcile(context.Background(), reconcileReq(testNAT66ShardName)); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil for a NotFound shard object", err)
	}
	assertNoAdvertisement(t, c)
	if _, ok := datapath.Programmed(); ok {
		t.Error("datapath still programmed after its EgressShard object disappeared")
	}
}
