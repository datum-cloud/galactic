// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// Root tests for issue #1270 against the real pinned maps.

const vrfTablesRouter = "router-a"

func vrfTablesRouterObj() *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: vrfTablesRouter, Namespace: "default"},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: vrfTablesNode},
			LocalASN:    65000,
			SRv6Locator: testLocator,
			NodeID:      5,
		},
	}
}

func vrfTablesInstance(vpc string, argument int32) *bgpv1alpha1.BGPVRFInstance {
	return &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: crdnames.BGPVRFInstanceName(vpc, vrfTablesNode), Namespace: "default"},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: vrfTablesRouter}},
			VRFID:              argument,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
		},
	}
}

// loadVRFTablesMaps loads the uSID datapath's maps under a fresh pin
// directory and opens vrf_table and egress_route_table from it.
func loadVRFTablesMaps(t *testing.T, name string) (string, *usidmap.Registry, *egressroutemap.EgressRouteTable) {
	t.Helper()
	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-gcsweep-%s-%d", name, os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	reg, regCloser, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	t.Cleanup(func() { _ = regCloser.Close() })
	egress, egressCloser, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedEgressRouteTable: %v", err)
	}
	t.Cleanup(func() { _ = egressCloser.Close() })
	return pinDir, reg, egress
}

// TestSweepEBPFVRFTable_RewritesStaleTableID registers a VPC's vrf_table
// entry on a table its kernel VRF no longer has, as after the VRF was
// recreated with no CNI ADD to re-register it, and checks that the sweep
// moves the entry to the VRF's table and keeps its egress kind.
func TestSweepEBPFVRFTable_RewritesStaleTableID(t *testing.T) {
	requireRoot(t)
	const argument = int32(10)
	withFakeLinks(t, []*netlink.Vrf{{LinkAttrs: netlink.LinkAttrs{Name: testVRFName, Index: 42}, Table: 9}}, nil)
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).
		WithObjects(vrfTablesRouterObj(), vrfTablesInstance("jU", argument)).Build()
	pinDir, reg, _ := loadVRFTablesMaps(t, "rewrite")

	block, err := blockFromLocator(t)
	if err != nil {
		t.Fatalf("derive block: %v", err)
	}
	if err := reg.VRF.Register(block, uint16(argument), 7, usidmap.EgressKindTap); err != nil {
		t.Fatalf("seed entry: %v", err)
	}

	result := SweepEBPFVRFTable(context.Background(), k8s, "default", vrfTablesNode, pinDir)
	if result.Errors != 0 || result.EBPFVRFEntriesRewritten != 1 {
		t.Errorf("result = %+v, want 1 entry rewritten and no errors", result)
	}
	entry, ok, err := reg.VRF.Get(block, uint16(argument))
	if err != nil || !ok {
		t.Fatalf("entry after sweep: ok=%v err=%v", ok, err)
	}
	if entry.VRFTableID != 9 || entry.EgressKind != usidmap.EgressKindTap {
		t.Errorf("entry = table %d kind %d, want table 9 kind %d (the CNI's egress kind kept)",
			entry.VRFTableID, entry.EgressKind, usidmap.EgressKindTap)
	}
}

// TestRecreatedVRFKeepsItsTableWhileAnotherVPCIsCreated deletes VPC A's kernel
// VRF the way garbage collection does, creates VPC B, then recreates A, with
// real VRFs and the real pinned maps. B must not be given A's table while A's
// state still references it, A must get its own table back, and after a
// sweep vrf_table and egress_route_table must route each VPC through its own
// table.
func TestRecreatedVRFKeepsItsTableWhileAnotherVPCIsCreated(t *testing.T) {
	requireRoot(t)
	const (
		vpcA, vpcB = "vtrka", "vtrkb"
		argA, argB = int32(10), int32(11)
	)
	t.Cleanup(func() { _ = vrf.Delete(vpcA); _ = vrf.Delete(vpcB) })
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(
		vrfTablesRouterObj(), vrfTablesInstance(vpcA, argA), vrfTablesInstance(vpcB, argB),
	).Build()
	pinDir, reg, egress := loadVRFTablesMaps(t, "recreate")
	block, err := blockFromLocator(t)
	if err != nil {
		t.Fatalf("derive block: %v", err)
	}
	_, prefixA, _ := net.ParseCIDR("2001:db8:a::/64")
	_, prefixB, _ := net.ParseCIDR("2001:db8:b::/64")

	// A attaches: its VRF, its vrf_table entry and an egress entry.
	if err := vrf.Add(vpcA); err != nil {
		t.Fatalf("Add(A): %v", err)
	}
	tableA, err := vrf.TableID(vpcA)
	if err != nil {
		t.Fatalf("TableID(A): %v", err)
	}
	if err := reg.VRF.Register(block, uint16(argA), tableA, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("register A: %v", err)
	}
	if err := egress.RegisterPassThrough(tableA, prefixA); err != nil {
		t.Fatalf("egress entry for A: %v", err)
	}

	// A's VRF is deleted while its BGPVRFInstance and map state remain.
	if _, err := vrf.DeleteIfUnused(intf.GenerateInterfaceNameVRF(vpcA)); err != nil {
		t.Fatalf("DeleteIfUnused(A): %v", err)
	}

	// B attaches meanwhile.
	if err := vrf.Add(vpcB); err != nil {
		t.Fatalf("Add(B): %v", err)
	}
	tableB, err := vrf.TableID(vpcB)
	if err != nil {
		t.Fatalf("TableID(B): %v", err)
	}
	if tableB == tableA {
		t.Fatalf("B was given table %d, which A's vrf_table and egress_route_table entries still use", tableA)
	}
	if err := reg.VRF.Register(block, uint16(argB), tableB, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("register B: %v", err)
	}
	if err := egress.RegisterPassThrough(tableB, prefixB); err != nil {
		t.Fatalf("egress entry for B: %v", err)
	}

	// A's VRF is recreated without a CNI ADD re-registering it.
	if err := vrf.Add(vpcA); err != nil {
		t.Fatalf("re-Add(A): %v", err)
	}
	if got, err := vrf.TableID(vpcA); err != nil || got != tableA {
		t.Fatalf("recreated A's table = %d, %v; want its own table %d", got, err, tableA)
	}

	result := SweepEBPFVRFTable(context.Background(), k8s, "default", vrfTablesNode, pinDir)
	if result.Errors != 0 {
		t.Errorf("result.Errors = %d, want 0", result.Errors)
	}
	for _, c := range []struct {
		name  string
		arg   int32
		table uint32
	}{{"A", argA, tableA}, {"B", argB, tableB}} {
		entry, ok, err := reg.VRF.Get(block, uint16(c.arg))
		if err != nil || !ok || entry.VRFTableID != c.table {
			t.Errorf("vrf_table entry for %s = table %d (ok=%v err=%v), want %d",
				c.name, entry.VRFTableID, ok, err, c.table)
		}
	}
	prefixes, err := egress.Prefixes()
	if err != nil {
		t.Fatalf("egress Prefixes: %v", err)
	}
	if _, ok := prefixes[tableA][prefixA.String()]; !ok {
		t.Errorf("A's egress entry left table %d", tableA)
	}
	if _, ok := prefixes[tableB][prefixA.String()]; ok {
		t.Errorf("A's egress entry is in B's table %d", tableB)
	}
	if _, ok := prefixes[tableB][prefixB.String()]; !ok {
		t.Errorf("B's egress entry left table %d", tableB)
	}
}
