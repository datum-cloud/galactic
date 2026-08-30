// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/nptv6map"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// testRouteTarget is the import/export route target value shared by every
// test fixture's BGPVRFInstance in this file; its exact value has no
// bearing on the eBPF vrf_table sweep logic under test.
const testRouteTarget = "65000:1"

// targetKindNode is BGPRouter's own TargetRef.Kind value, shared by every
// test fixture's BGPRouter in this file (goconst).
const targetKindNode = "Node"

// testLocator is the SRv6 locator every test fixture's BGPRouter in this
// file uses; its exact value has no bearing on the eBPF vrf_table sweep
// logic under test, only that blockFromLocator can derive a real Block
// from it (goconst/unparam: every caller wants the same one).
const testLocator = "2001:db8:1::/48"

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to load real BPF maps; re-run via sudo")
	}
}

func gcTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme (client-go): %v", err)
	}
	if err := bgpv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme (bgpv1alpha1): %v", err)
	}
	return s
}

// TestSweepEBPFVRFTable_MissingPinDirIsNoOp covers the startup-ordering
// case: the sweep ticker can fire before the "run" container has finished
// loading/pinning the eBPF datapath, so /sys/fs/bpf/galactic (or wherever
// pinDir points) may not exist yet -- SweepEBPFVRFTable must not treat
// that as an error.
func TestSweepEBPFVRFTable_MissingPinDirIsNoOp(t *testing.T) {
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).Build()
	result := SweepEBPFVRFTable(context.Background(), k8s, "default", "node-a", "/sys/fs/bpf/galactic-does-not-exist")
	if result.Errors != 0 || result.EBPFVRFEntriesRemoved != 0 {
		t.Errorf("result = %+v, want a zero-value result (no-op)", result)
	}
}

// TestSweepEBPFVRFTable_RemovesStaleKeepsLive is Milestone 7.3's exit
// criterion. It seeds two vrf_table entries against a real, pinned map:
// one whose BGPVRFInstance/BGPRouter CRD pair is present in the fake k8s
// client (must survive), and one whose BGPVRFInstance CRD is absent (must
// be removed) -- both keyed by the same (Block, Argument) pair
// registerEBPFDatapath (Milestone 7.1) would register: uformat.Block
// (locator) and inst.Spec.VRFID directly as the Argument (Milestone 6.1).
func TestSweepEBPFVRFTable_RemovesStaleKeepsLive(t *testing.T) {
	requireRoot(t)

	const (
		namespace  = "default"
		nodeName   = "node-a"
		routerName = "router-a"
		liveVRFID  = int32(10)
		staleVRFID = int32(20)
	)

	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: routerName, Namespace: namespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: nodeName},
			LocalASN:    65000,
			SRv6Locator: testLocator,
			NodeID:      5,
		},
	}
	liveInst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "live-vrf", Namespace: namespace},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			VRFID:              liveVRFID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
		},
	}
	// staleVRFID's BGPVRFInstance is deliberately NOT created -- only
	// live-vrf exists in the fake client.
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(router, liveInst).Build()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-gcsweep-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	defer func() { _ = closer.Close() }()

	block, err := blockFromLocator(t)
	if err != nil {
		t.Fatalf("derive block: %v", err)
	}
	// inst.Spec.VRFID is the real Argument value directly (Milestone 6.1) --
	// liveVRFID/staleVRFID are chosen small enough to already be valid
	// Arguments, no fold needed.
	liveArgument := uint16(liveVRFID)
	staleArgument := uint16(staleVRFID)

	if err := reg.VRF.Register(block, liveArgument, 0x111111, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed live entry: %v", err)
	}
	if err := reg.VRF.Register(block, staleArgument, 0x222222, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed stale entry: %v", err)
	}

	result := SweepEBPFVRFTable(context.Background(), k8s, namespace, nodeName, pinDir)
	if result.Errors != 0 {
		t.Errorf("result.Errors = %d, want 0", result.Errors)
	}
	if result.EBPFVRFEntriesRemoved != 1 {
		t.Errorf("result.EBPFVRFEntriesRemoved = %d, want 1", result.EBPFVRFEntriesRemoved)
	}

	if _, ok, err := reg.VRF.Get(block, liveArgument); err != nil || !ok {
		t.Errorf("live entry after sweep: ok=%v err=%v, want ok=true (must survive)", ok, err)
	}
	if _, ok, err := reg.VRF.Get(block, staleArgument); err != nil || ok {
		t.Errorf("stale entry after sweep: ok=%v err=%v, want ok=false (must be removed)", ok, err)
	}
}

// TestSweepEBPFVRFTable_PreservesIngressSidecarReservedBlock reproduces the
// bug this exemption fixes: internal/ingresssidecar registers its own
// vrf_table entries under uformat.BlockMax, a block
// deliberately reserved so it never collides with a real BGPRouter locator,
// with no BGPVRFInstance CRD behind it at all -- that sidecar owns their
// lifecycle itself. Before the fix, every such entry was invisible to this
// sweep's CRD-built live set and got removed as an orphan on the very next
// tick, silently blackholing that sidecar's own outbound connections to VPC
// backends. A genuinely stale entry under an ordinary, non-reserved block
// must still be removed -- this guards the exemption's scope, not just its
// existence.
func TestSweepEBPFVRFTable_PreservesIngressSidecarReservedBlock(t *testing.T) {
	requireRoot(t)

	const (
		namespace  = "default"
		nodeName   = "node-a"
		routerName = "router-a"
		staleVRFID = int32(20)
	)

	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: routerName, Namespace: namespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: nodeName},
			LocalASN:    65000,
			SRv6Locator: testLocator,
			NodeID:      5,
		},
	}
	// No BGPVRFInstance at all -- neither the reserved-block entry nor the
	// ordinary stale one has any CRD backing it.
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(router).Build()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-gcsweep-reserved-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	defer func() { _ = closer.Close() }()

	ordinaryBlock, err := blockFromLocator(t)
	if err != nil {
		t.Fatalf("derive block: %v", err)
	}
	const reservedArgument = uint16(2) // matches the demo2loc VRF table id observed live
	staleArgument := uint16(staleVRFID)

	if err := reg.VRF.Register(uformat.BlockMax, reservedArgument, 0x444444, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed ingress-sidecar reserved-block entry: %v", err)
	}
	if err := reg.VRF.Register(ordinaryBlock, staleArgument, 0x555555, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed ordinary stale entry: %v", err)
	}

	result := SweepEBPFVRFTable(context.Background(), k8s, namespace, nodeName, pinDir)
	if result.Errors != 0 {
		t.Errorf("result.Errors = %d, want 0", result.Errors)
	}
	if result.EBPFVRFEntriesRemoved != 1 {
		t.Errorf("result.EBPFVRFEntriesRemoved = %d, want 1 (only the ordinary stale entry)", result.EBPFVRFEntriesRemoved)
	}

	if _, ok, err := reg.VRF.Get(uformat.BlockMax, reservedArgument); err != nil || !ok {
		t.Errorf("reserved-block entry after sweep: ok=%v err=%v, want ok=true (must survive, no CRD needed)", ok, err)
	}
	if _, ok, err := reg.VRF.Get(ordinaryBlock, staleArgument); err != nil || ok {
		t.Errorf("ordinary stale entry after sweep: ok=%v err=%v, want ok=false (still must be removed)", ok, err)
	}
}

// TestSweepEBPFVRFTable_NoRoutersForNodeSkipsSweep guards against a
// regression of the fix where routersForNode returning zero routers (e.g. a
// transient BGPRouter listing/cache hiccup, or the router being
// renamed/recreated between ticks) was indistinguishable from "genuinely
// nothing is live" -- causing every vrf_table entry on the node, including
// ones with a perfectly live BGPVRFInstance, to be reconciled away with no
// repair path. A tick that finds no router for this node at all must leave
// vrf_table untouched.
func TestSweepEBPFVRFTable_NoRoutersForNodeSkipsSweep(t *testing.T) {
	requireRoot(t)

	const (
		namespace = "default"
		nodeName  = "node-a"
		vrfID     = int32(10)
	)

	// Deliberately no BGPRouter object at all for nodeName -- only the
	// BGPVRFInstance exists, referencing a router name that isn't present.
	inst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "orphaned-router-ref", Namespace: namespace},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: "router-a"}},
			VRFID:              vrfID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
		},
	}
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(inst).Build()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-gcsweep-norouter-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	defer func() { _ = closer.Close() }()

	block, err := blockFromLocator(t)
	if err != nil {
		t.Fatalf("derive block: %v", err)
	}
	argument := uint16(vrfID)
	if err := reg.VRF.Register(block, argument, 0x333333, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed entry: %v", err)
	}

	result := SweepEBPFVRFTable(context.Background(), k8s, namespace, nodeName, pinDir)
	if result.Errors != 0 {
		t.Errorf("result.Errors = %d, want 0 (no-router is a skip, not an error)", result.Errors)
	}
	if result.EBPFVRFEntriesRemoved != 0 {
		t.Errorf("result.EBPFVRFEntriesRemoved = %d, want 0 (must not reconcile against an empty live set)",
			result.EBPFVRFEntriesRemoved)
	}
	if _, ok, err := reg.VRF.Get(block, argument); err != nil || !ok {
		t.Errorf("entry after no-router sweep: ok=%v err=%v, want ok=true (must survive)", ok, err)
	}
}

// blockFromLocator mirrors registerEBPFDatapath's/SweepEBPFVRFTable's own
// locator-to-Block derivation for testLocator, kept local to this test file
// to avoid importing internal/cni (which would be a layering inversion)
// just for one helper. No caller in this file ever needs a Block derived
// from any other locator (unparam), since testLocator's exact value has no
// bearing on the eBPF vrf_table sweep logic under test.
func blockFromLocator(t *testing.T) (uint64, error) {
	t.Helper()
	prefix, err := netip.ParsePrefix(testLocator)
	if err != nil {
		return 0, err
	}
	return uformat.Block(prefix.Addr())
}

// TestSweepEBPFNPTv6Table_MissingPinDirIsNoOp mirrors
// TestSweepEBPFVRFTable_MissingPinDirIsNoOp for the nptv6_table sweep.
func TestSweepEBPFNPTv6Table_MissingPinDirIsNoOp(t *testing.T) {
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).Build()
	result := SweepEBPFNPTv6Table(context.Background(), k8s, "default", "node-a", "/sys/fs/bpf/galactic-does-not-exist")
	if result.Errors != 0 || result.EBPFNPTv6EntriesRemoved != 0 {
		t.Errorf("result = %+v, want a zero-value result (no-op)", result)
	}
}

// TestSweepEBPFNPTv6Table_RegistersLiveRemovesStale is nptv6_table's own
// exit criterion, mirroring TestSweepEBPFVRFTable_RemovesStaleKeepsLive:
// unlike vrf_table, this function is nptv6_table's *only* writer (see its
// own doc comment), so it must both register a live BGPVRFInstance's own
// NPTv6 mapping AND remove a stale one whose CRD is absent, in the same
// call.
func TestSweepEBPFNPTv6Table_RegistersLiveRemovesStale(t *testing.T) {
	requireRoot(t)

	const (
		namespace  = "default"
		nodeName   = "node-a"
		routerName = "router-a"
		liveVRFID  = int32(10)
		staleVRFID = int32(20)
	)

	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: routerName, Namespace: namespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: nodeName},
			LocalASN:    65000,
			SRv6Locator: testLocator,
			NodeID:      5,
		},
	}
	liveInst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "live-vrf", Namespace: namespace},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			VRFID:              liveVRFID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			NPTv6: &bgpv1alpha1.NPTv6Spec{
				ULAPrefix:    "fd00:1::/48",
				PublicPrefix: "2001:db8:2::/48",
			},
		},
	}
	// staleVRFID's BGPVRFInstance is deliberately NOT created -- only
	// live-vrf exists in the fake client; its nptv6_table row is seeded
	// directly below to simulate one left behind by a deleted CRD.
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(router, liveInst).Build()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-gcsweep-nptv6-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	table, closer, err := nptv6map.OpenPinned(pinDir)
	if err != nil {
		t.Fatalf("nptv6map.OpenPinned: %v", err)
	}
	defer func() { _ = closer.Close() }()

	block, err := blockFromLocator(t)
	if err != nil {
		t.Fatalf("derive block: %v", err)
	}
	staleArgument := uint16(staleVRFID)
	staleMapping, err := buildNPTv6Mapping(&bgpv1alpha1.NPTv6Spec{
		ULAPrefix: "fd00:9::/48", PublicPrefix: "2001:db8:9::/48",
	})
	if err != nil {
		t.Fatalf("buildNPTv6Mapping: %v", err)
	}
	if err := table.Register(block, staleArgument, staleMapping); err != nil {
		t.Fatalf("seed stale entry: %v", err)
	}

	result := SweepEBPFNPTv6Table(context.Background(), k8s, namespace, nodeName, pinDir)
	if result.Errors != 0 {
		t.Errorf("result.Errors = %d, want 0", result.Errors)
	}
	if result.EBPFNPTv6EntriesRemoved != 1 {
		t.Errorf("result.EBPFNPTv6EntriesRemoved = %d, want 1", result.EBPFNPTv6EntriesRemoved)
	}

	if _, ok, err := table.Get(block, uint16(liveVRFID)); err != nil || !ok {
		t.Errorf("live entry after sweep: ok=%v err=%v, want ok=true (must be registered)", ok, err)
	}
	if _, ok, err := table.Get(block, staleArgument); err != nil || ok {
		t.Errorf("stale entry after sweep: ok=%v err=%v, want ok=false (must be removed)", ok, err)
	}
}
