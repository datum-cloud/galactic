// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// TestInstallSidecarReturn_MarksTheInterfaceInfra installs a return path in
// a private namespace against freshly loaded maps: the gateway's host
// interface gets an infra row alongside its route. An endpoint naming an
// interface that holds a tenant row is refused before anything points at
// that interface, and the tenant row is left intact.
func TestInstallSidecarReturn_MarksTheInterfaceInfra(t *testing.T) {
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

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-installer-sidecarreturn-%d", os.Getpid())
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

	links := map[string]int{}
	for _, name := range []string{"gw-h", "tenant-h"} {
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{name, name + "p"} {
			l, err := netlink.LinkByName(n)
			if err != nil {
				t.Fatal(err)
			}
			if err := netlink.LinkSetUp(l); err != nil {
				t.Fatal(err)
			}
			links[n] = l.Attrs().Index
		}
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	const block = 0xfc0000010000

	gateway := sidecarEndpoint{
		advName: "gateway", addr: netip.MustParseAddr(testReturnAddr2), vrfID: 2,
		hostIfindex: links["gw-h"], hostMAC: mac,
	}
	if err := installSidecarReturn(registry, policy, block, gateway); err != nil {
		t.Fatalf("install: %v", err)
	}
	var row prog.UsidTpIfaceValue
	if err := policy.Interfaces.Lookup(uint32(links["gw-h"]), &row); err != nil || row.Kind != tpmap.KindInfra {
		t.Errorf("gateway interface row = %+v, %v; want infra", row, err)
	}
	if routes := returnRoutes(t, gateway.vrfID); len(routes) != 1 || routes[0].LinkIndex != links["gw-h"] {
		t.Errorf("gateway return routes = %v, want one via gw-h", routes)
	}

	const token = 0x5eed
	if err := policy.PutInterface(uint32(links["tenant-h"]), token, tpmap.KindTenant); err != nil {
		t.Fatal(err)
	}
	stale := sidecarEndpoint{
		advName: "stale", addr: netip.MustParseAddr(testReturnAddr3), vrfID: 3,
		hostIfindex: links["tenant-h"], hostMAC: mac,
	}
	if err := installSidecarReturn(registry, policy, block, stale); !errors.Is(err, tpmap.ErrTenantInterface) {
		t.Fatalf("install over a tenant interface: err = %v, want ErrTenantInterface", err)
	}
	if routes := returnRoutes(t, stale.vrfID); len(routes) != 0 {
		t.Errorf("refused endpoint left return routes %v, want none", routes)
	}
	if err := policy.Interfaces.Lookup(uint32(links["tenant-h"]), &row); err != nil ||
		row.Kind != tpmap.KindTenant || row.PolicyToken != token {
		t.Errorf("tenant row = %+v, %v; want it unchanged", row, err)
	}
}

// returnRoutes lists the routes in the return table for vrfID.
func returnRoutes(t *testing.T, vrfID uint16) []netlink.Route {
	t.Helper()
	table, err := sidecarReturnTableID(vrfID)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatal(err)
	}
	return routes
}
