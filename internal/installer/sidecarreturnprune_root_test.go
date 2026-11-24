// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"go.datum.net/galactic/internal/cni/vpcfence"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// The fixture TestPruneRetiredSidecarReturn writes: a retired row whose VPC
// resolves and has no VRF, a retired row whose VPC resolves and still has its
// host VRF, a retired row whose VPC does not resolve, a CNI row in a host
// table, and an infra row no retired route names.
const (
	pruneTestBlock      = uint64(0x20010db88002)
	pruneTestRetired    = uint16(5)
	pruneTestRestored   = uint16(8)
	pruneTestVRFTable   = 200
	pruneTestUnknown    = uint16(7)
	pruneTestCNI        = uint16(6)
	pruneTestHostTable  = 100
	pruneTestOtherInfra = uint32(77)
)

// TestPruneRetiredSidecarReturn writes what the retired sidecar return path
// left on a node, beside rows and routes other writers own, into a private
// namespace and freshly loaded maps. The prune removes the leftovers, keeps
// the rest, keeps a retired vrf_table row whose VPC is unknown, and finds
// nothing on a second run.
func TestPruneRetiredSidecarReturn(t *testing.T) {
	requireRoot(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close(); _ = netns.Set(orig) }()

	prevDir := vpcfence.Dir
	vpcfence.Dir = t.TempDir()
	t.Cleanup(func() { vpcfence.Dir = prevDir })

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-installer-sidecarreturnprune-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	policy, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "gw0"}, PeerName: "gw1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName("gw0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	ifindex := link.Attrs().Index

	gateway := net.ParseIP("2001:db8:aa::5")
	host := &net.IPNet{IP: gateway, Mask: net.CIDRMask(128, 128)}
	for _, table := range []int{sidecarReturnTableBase + int(pruneTestRetired), pruneTestHostTable} {
		if err := netlink.RouteAdd(&netlink.Route{Dst: host, LinkIndex: ifindex, Table: table}); err != nil {
			t.Fatalf("add route in table %#x: %v", table, err)
		}
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:05")
	if err := netlink.NeighSet(&netlink.Neigh{LinkIndex: ifindex, Family: netlink.FAMILY_V6,
		State: netlink.NUD_PERMANENT, IP: gateway, HardwareAddr: mac}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		argument uint16
		table    uint32
	}{
		{pruneTestRetired, sidecarReturnTableBase + uint32(pruneTestRetired)},
		{pruneTestRestored, sidecarReturnTableBase + uint32(pruneTestRestored)},
		{pruneTestUnknown, sidecarReturnTableBase + uint32(pruneTestUnknown)},
		{pruneTestCNI, pruneTestHostTable},
	} {
		if err := registry.VRF.Register(pruneTestBlock, r.argument, r.table, usidmap.EgressKindVeth); err != nil {
			t.Fatal(err)
		}
	}
	for _, i := range []uint32{uint32(ifindex), pruneTestOtherInfra} { //nolint:gosec // a test ifindex
		if err := policy.PutInfra(i); err != nil {
			t.Fatal(err)
		}
	}

	// vpctwo's host VRF still exists, so its row must point at that VRF again.
	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF("vpctwo")},
		Table: pruneTestVRFTable}); err != nil {
		t.Fatal(err)
	}
	vpcOf := func(argument uint16) (string, bool) {
		switch argument {
		case pruneTestRetired:
			return "vpcone", true
		case pruneTestRestored:
			return "vpctwo", true
		}
		return "", false
	}
	pruned, err := pruneRetiredSidecarReturn(context.Background(), pinDir, vpcOf, sidecarReturnKeep{})
	if err != nil {
		t.Fatalf("pruneRetiredSidecarReturn: %v", err)
	}
	want := retiredSidecarReturnPruned{vrfRows: 2, routes: 1, neighbors: 1, infraRows: 1, vrfRowsKept: 1}
	if pruned != want {
		t.Errorf("pruned = %+v, want %+v", pruned, want)
	}

	checkRetiredSidecarReturnPruned(t, registry, policy, ifindex, gateway)

	again, err := pruneRetiredSidecarReturn(context.Background(), pinDir, vpcOf, sidecarReturnKeep{})
	if err != nil {
		t.Fatalf("second pruneRetiredSidecarReturn: %v", err)
	}
	if want := (retiredSidecarReturnPruned{vrfRowsKept: 1}); again != want {
		t.Errorf("second prune = %+v, want %+v", again, want)
	}
}

// checkRetiredSidecarReturnPruned asserts the fixture's state after one prune.
func checkRetiredSidecarReturnPruned(
	t *testing.T, registry *usidmap.Registry, policy *tpmap.Maps, ifindex int, gateway net.IP,
) {
	t.Helper()
	if _, ok, _ := registry.VRF.Get(pruneTestBlock, pruneTestRetired); ok {
		t.Error("retired vrf_table row kept")
	}
	if row, ok, err := registry.VRF.Get(pruneTestBlock, pruneTestRestored); err != nil || !ok ||
		row.VRFTableID != pruneTestVRFTable || row.EgressKind != usidmap.EgressKindVeth {
		t.Errorf("retired row of a VPC with a VRF = %+v (present %t, err %v), want it pointed at table %d",
			row, ok, err, pruneTestVRFTable)
	}
	for _, a := range []uint16{pruneTestUnknown, pruneTestCNI} {
		if _, ok, err := registry.VRF.Get(pruneTestBlock, a); err != nil || !ok {
			t.Errorf("vrf_table row for argument %d removed: %v", a, err)
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: sidecarReturnTableBase + int(pruneTestRetired)}, netlink.RT_FILTER_TABLE)
	if err != nil || len(routes) != 0 {
		t.Errorf("retired table holds %v (err %v), want empty", routes, err)
	}
	routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: pruneTestHostTable}, netlink.RT_FILTER_TABLE)
	if err != nil || len(routes) != 1 {
		t.Errorf("host table holds %v (err %v), want its one route", routes, err)
	}
	neighs, err := netlink.NeighList(ifindex, netlink.FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range neighs {
		if n.IP.Equal(gateway) && n.State&netlink.NUD_PERMANENT != 0 {
			t.Error("permanent neighbor for the gateway address kept")
		}
	}
	if infra, _ := policy.IsInfra(uint32(ifindex)); infra { //nolint:gosec // a test ifindex
		t.Error("infra row of the retired route's interface kept")
	}
	if infra, _ := policy.IsInfra(pruneTestOtherInfra); !infra {
		t.Error("unrelated infra row removed")
	}
}
