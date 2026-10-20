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
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// TestListRoutes_InventoriesOnlyThisPodsRoutes: the startup inventory finds a
// route EnsureRoute wrote into egress_route_table, with its SID, by the
// redirect route in this pod's own namespace, and leaves an entry under the
// same table ID with no redirect route, which may be a sibling pod's, out.
func TestListRoutes_InventoriesOnlyThisPodsRoutes(t *testing.T) {
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

	const tableID = vrf.SidecarTableIDBase + 9
	owned := mustPrefix(t, "fd00:5::1")
	foreign := mustPrefix(t, "fd00:5::2")
	_, owned4, _ := net.ParseCIDR("192.0.2.1/32")
	_, lost, _ := net.ParseCIDR("fd00:5::3/128") // redirect route, map entry gone
	sid := net.ParseIP("fd00:99::1")

	err = nsObj.Do(func(_ ns.NetNS) error {
		vrfLink := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "ivstestinv"}, Table: tableID}
		if err := netlink.LinkAdd(vrfLink); err != nil {
			return fmt.Errorf("add VRF: %w", err)
		}
		if err := netlink.LinkSetUp(vrfLink); err != nil {
			return fmt.Errorf("set VRF up: %w", err)
		}
		table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(ebpfPinDir)
		if err != nil {
			return err
		}
		defer func() { _ = closer.Close() }()
		for _, p := range []*net.IPNet{owned, owned4, foreign} {
			if err := table.Register(tableID, p, sid); err != nil {
				return fmt.Errorf("register %s: %w", p, err)
			}
		}
		for _, p := range []*net.IPNet{owned, owned4, lost} {
			if err := ensureRedirectRoute(p, tableID); err != nil {
				return err
			}
		}

		routes, err := listRoutes(tableID)
		if err != nil {
			return fmt.Errorf("listRoutes: %w", err)
		}
		got := map[string]string{}
		for _, r := range routes {
			got[r.Prefix.String()] = r.SID.String()
		}
		want := map[string]string{
			owned.String(): sid.String(), owned4.String(): sid.String(), lost.String(): net.IP(nil).String(),
		}
		if len(got) != len(want) {
			return fmt.Errorf("listRoutes = %v, want %v", got, want)
		}
		for k, v := range want {
			if got[k] != v {
				return fmt.Errorf("listRoutes = %v, want %v", got, want)
			}
		}
		if _, ok, err := table.Lookup(tableID, foreign); err != nil || !ok {
			return fmt.Errorf("the entry with no redirect route was touched: ok=%v err=%w", ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestListRoutes_SkipsGatewayReturnRoute: the gateway return route also leaves
// the main table through the VRF device, but for an address the VRF holds.
// Inventorying it would seed an unclaimed route the sweep tears down, cutting
// every VPC present at startup off from its replies.
func TestListRoutes_SkipsGatewayReturnRoute(t *testing.T) {
	requireRoot(t)
	setUpTestPinDir(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	const tableID = vrf.SidecarTableIDBase + 10
	backend := mustPrefix(t, "fd00:6::1")
	gateway := mustPrefix(t, "fd42:0:2::1")

	err = nsObj.Do(func(_ ns.NetNS) error {
		vrfLink := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "ivstestgw"}, Table: tableID}
		if err := netlink.LinkAdd(vrfLink); err != nil {
			return fmt.Errorf("add VRF: %w", err)
		}
		if err := netlink.LinkSetUp(vrfLink); err != nil {
			return fmt.Errorf("set VRF up: %w", err)
		}
		inner := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ivstestgwin", MasterIndex: vrfLink.Attrs().Index}}
		if err := netlink.LinkAdd(inner); err != nil {
			return fmt.Errorf("add VRF slave: %w", err)
		}
		if err := netlink.LinkSetUp(inner); err != nil {
			return fmt.Errorf("set VRF slave up: %w", err)
		}
		if err := netlink.AddrAdd(inner, &netlink.Addr{IPNet: gateway, Flags: unix.IFA_F_NODAD}); err != nil {
			return fmt.Errorf("assign gateway address: %w", err)
		}
		if err := netlink.RouteReplace(&netlink.Route{
			Dst: gateway, Table: unix.RT_TABLE_MAIN, LinkIndex: vrfLink.Attrs().Index,
		}); err != nil {
			return fmt.Errorf("install gateway return route: %w", err)
		}
		if err := ensureRedirectRoute(backend, tableID); err != nil {
			return err
		}

		routes, err := listRoutes(tableID)
		if err != nil {
			return fmt.Errorf("listRoutes: %w", err)
		}
		if len(routes) != 1 || routes[0].Prefix.String() != backend.String() {
			return fmt.Errorf("listRoutes = %v, want only the backend redirect %s", routes, backend)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
