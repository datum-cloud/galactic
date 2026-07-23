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
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

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
		locator    = "2001:db8:1::/48"
		liveVRFID  = int32(10)
		staleVRFID = int32(20)
	)

	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: routerName, Namespace: namespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: "Node", Name: nodeName},
			LocalASN:    65000,
			SRv6Locator: locator,
			NodeID:      5,
		},
	}
	liveInst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "live-vrf", Namespace: namespace},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			VRFID:              liveVRFID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:1"}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: "65000:1"}},
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

	block, err := blockFromLocator(t, locator)
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

// blockFromLocator mirrors registerEBPFDatapath's/SweepEBPFVRFTable's own
// locator-to-Block derivation, kept local to this test file to avoid
// importing internal/cni (which would be a layering inversion) just for
// one helper.
func blockFromLocator(t *testing.T, locator string) (uint64, error) {
	t.Helper()
	prefix, err := netip.ParsePrefix(locator)
	if err != nil {
		return 0, err
	}
	return uformat.Block(prefix.Addr())
}
