// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"fmt"
	"net"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/sidecarmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// Host rows the prune must leave: a table, Block and ifindexes outside the
// sidecar's ranges.
const (
	hostTestTable   = 100
	hostTestBlock   = uint64(0x20010db80000)
	hostTestIfindex = 5
	hostTestInfra   = 7
)

// TestPruneInPodEncapsulation_RemovesWhatAnInPodSidecarLeft builds what a
// sidecar with in-pod encapsulation leaves in its pod and the node's maps,
// with its real code: a VRF with its egress veth pair and datapath rows, a
// backend's egress_route_table row and main-table redirect route, and a
// kernel seg6 route. The prune removes all of it, keeps the VRF, its
// unreachable default and every host row, and a second prune removes
// nothing.
func TestPruneInPodEncapsulation_RemovesWhatAnInPodSidecarLeft(t *testing.T) {
	requireRoot(t)
	setUpTestPinDir(t)
	restore := egressroutemap.OverrideResolverForTest(
		func(net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
			return 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, nil
		})
	t.Cleanup(restore)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	const tableID = vrf.SidecarTableIDBase + 31
	backend := mustPrefix(t, "2001:db8:5::1")
	_, seg6Dst, _ := net.ParseCIDR("2001:db8:6::/64")
	_, hostPrefix, _ := net.ParseCIDR("2001:db8:7::/64")
	sid := net.ParseIP("2001:db8:99::1")

	err = nsObj.Do(func(_ ns.NetNS) error {
		vrfLink := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "GprunetstV"}, Table: tableID}
		if err := netlink.LinkAdd(vrfLink); err != nil {
			return fmt.Errorf("add VRF: %w", err)
		}
		if err := netlink.LinkSetUp(vrfLink); err != nil {
			return err
		}
		if err := netlink.RouteReplace(&netlink.Route{Table: int(tableID), Type: unix.RTN_UNREACHABLE,
			Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Priority: vrf.UnreachableDefaultMetric}); err != nil {
			return fmt.Errorf("unreachable default: %w", err)
		}
		if err := ensureEgressDatapath(tableID); err != nil {
			return fmt.Errorf("ensureEgressDatapath: %w", err)
		}
		if err := ensureRedirectRoute(backend, tableID); err != nil {
			return err
		}
		if err := netlink.RouteAdd(&netlink.Route{Table: int(tableID), Dst: seg6Dst, LinkIndex: vrfLink.Index,
			Encap: &netlink.SEG6Encap{Mode: nl.SEG6_IPTUN_MODE_ENCAP, Segments: []net.IP{sid}}}); err != nil {
			return fmt.Errorf("seg6 route: %w", err)
		}
		if err := seedPruneRows(tableID, backend, hostPrefix, sid); err != nil {
			return err
		}

		res, err := PruneInPodEncapsulation()
		if err != nil {
			return fmt.Errorf("prune: %w", err)
		}
		if res.VethLinks != 1 || res.RedirectRoutes != 1 || res.Seg6Routes != 1 || res.MapRows == 0 {
			t.Errorf("prune result = %+v, want one veth pair, one redirect route, one seg6 route and the map rows", res)
		}
		checkPruned(t, vrfLink, tableID, backend)
		if err := checkHostRows(hostPrefix); err != nil {
			return err
		}

		again, err := PruneInPodEncapsulation()
		if err != nil || again.Total() != 0 {
			t.Errorf("second prune = %+v, %v; want nothing removed", again, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// seedPruneRows writes the backend's sidecar egress_route_table row, as
// EnsureRoute does, and one host row in each map.
func seedPruneRows(tableID uint32, backend, hostPrefix *net.IPNet, sid net.IP) error {
	routes, closer, err := egressroutemap.OpenPinnedEgressRouteTable(ebpfPinDir)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	if err := routes.Register(tableID, backend, sid); err != nil {
		return fmt.Errorf("register sidecar egress route: %w", err)
	}
	if err := routes.Register(hostTestTable, hostPrefix, sid); err != nil {
		return fmt.Errorf("register host egress route: %w", err)
	}
	registry, rcloser, err := usidmap.OpenPinnedRegistry(ebpfPinDir)
	if err != nil {
		return err
	}
	defer func() { _ = rcloser.Close() }()
	if err := registry.VRF.Register(hostTestBlock, 1, hostTestTable, usidmap.EgressKindVeth); err != nil {
		return fmt.Errorf("register host vrf_table row: %w", err)
	}
	ifindexTable, icloser, err := ifindexvrfmap.OpenPinned(ebpfPinDir)
	if err != nil {
		return err
	}
	defer func() { _ = icloser.Close() }()
	if err := ifindexTable.Register(hostTestIfindex, hostTestBlock, 1); err != nil {
		return fmt.Errorf("register host ifindex_vrf_table row: %w", err)
	}
	return tpmap.PutPinnedInfra(ebpfPinDir, hostTestInfra)
}

// checkPruned checks that the in-pod encapsulation of tableID's VRF is gone
// and the VRF, with its unreachable default, is not.
func checkPruned(t *testing.T, vrfLink *netlink.Vrf, tableID uint32, backend *net.IPNet) {
	t.Helper()
	if _, err := netlink.LinkByName(vrfLink.Name); err != nil {
		t.Errorf("VRF %s removed: %v", vrfLink.Name, err)
	}
	inner, peer := egressVethNames(tableID)
	for _, name := range []string{inner, peer} {
		if _, err := netlink.LinkByName(name); err == nil {
			t.Errorf("egress veth %s survived the prune", name)
		}
	}
	redirects, err := redirectPrefixes(vrfLink.Index, nil)
	if err != nil || len(redirects) != 0 {
		t.Errorf("main-table redirect routes into %s = %v, %v; want none (had %s)", vrfLink.Name, redirects, err, backend)
	}
	seg6, err := legacySeg6Routes(tableID)
	if err != nil || len(seg6) != 0 {
		t.Errorf("seg6 routes in table %d = %v, %v; want none", tableID, seg6, err)
	}
	unreachable, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: int(tableID), Type: unix.RTN_UNREACHABLE}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
	if err != nil || len(unreachable) != 1 {
		t.Errorf("table %d unreachable routes = %+v, %v; want the VRF's unreachable default", tableID, unreachable, err)
	}

	maps, closer, err := sidecarmap.OpenPinned(ebpfPinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	argument, err := argumentForTableID(tableID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := maps.VRF.Get(ingressSidecarBlock, argument); err != nil || ok {
		t.Errorf("sidecar vrf_table row present = %t, %v; want gone", ok, err)
	}
	peerIndex := ifindexvrfmap.SidecarIfindex(argument)
	if _, ok, err := maps.Ifindex.Get(peerIndex); err != nil || ok {
		t.Errorf("sidecar ifindex_vrf_table row present = %t, %v; want gone", ok, err)
	}
	if maps.Policy != nil {
		if ok, err := maps.Policy.IsInfra(peerIndex); err != nil || ok {
			t.Errorf("sidecar tp_iface_table infra row present = %t, %v; want gone", ok, err)
		}
	}
	byTable, err := maps.EgressRoute.Prefixes()
	if err != nil {
		t.Fatal(err)
	}
	if rows := byTable[tableID]; len(rows) != 0 {
		t.Errorf("sidecar egress_route_table rows for table %d = %v, want none", tableID, rows)
	}
}

// checkHostRows checks that every host row seedPruneRows wrote is still
// there.
func checkHostRows(hostPrefix *net.IPNet) error {
	maps, closer, err := sidecarmap.OpenPinned(ebpfPinDir)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	if _, ok, err := maps.VRF.Get(hostTestBlock, 1); err != nil || !ok {
		return fmt.Errorf("host vrf_table row present = %t, %w; want kept", ok, err)
	}
	if _, ok, err := maps.Ifindex.Get(hostTestIfindex); err != nil || !ok {
		return fmt.Errorf("host ifindex_vrf_table row present = %t, %w; want kept", ok, err)
	}
	if maps.Policy != nil {
		if ok, err := maps.Policy.IsInfra(hostTestInfra); err != nil || !ok {
			return fmt.Errorf("host tp_iface_table infra row present = %t, %w; want kept", ok, err)
		}
	}
	if _, ok, err := maps.EgressRoute.Lookup(hostTestTable, hostPrefix); err != nil || !ok {
		return fmt.Errorf("host egress_route_table row present = %t, %w; want kept", ok, err)
	}
	return nil
}
