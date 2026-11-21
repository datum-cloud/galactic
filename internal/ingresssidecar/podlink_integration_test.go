// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/vrf"
)

// localRoutes returns the routes configurePodLink made in table, by
// destination, with their link and gateway.
func localRoutes(t *testing.T, table uint32) map[netip.Addr]netlink.Route {
	t.Helper()
	have, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: int(table), Protocol: podLinkProtocol},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		t.Fatal(err)
	}
	out := map[netip.Addr]netlink.Route{}
	for _, r := range have {
		if a, ok := routeDst(r); ok {
			out[a] = r
		}
	}
	return out
}

// TestConfigurePodLink_TwoVPCsShareABackendAddress configures the pod ends of
// two VPCs' routed links, which Worker would have moved into the pod, with
// the same gateway address and a Local backend at the same address. Each
// VPC's route to that backend leaves through its own link in its own VRF,
// a VRF that is not created yet is reported as such, and a backend that
// stops being Local loses only its own route.
func TestConfigurePodLink_TwoVPCsShareABackendAddress(t *testing.T) {
	requireRoot(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	gw := netip.MustParseAddr("2001:db8:ff::1")
	backend := netip.MustParseAddr("2001:db8:1::10")
	other := netip.MustParseAddr("2001:db8:1::20")
	hostLL := netip.MustParseAddr("fe80::1")

	err = nsObj.Do(func(_ ns.NetNS) error {
		type vpcLink struct {
			vrf, pod, peer string
			table          uint32
		}
		links := []vpcLink{
			{vrf: "GtestvrfaV", pod: "podA", peer: "hostA", table: vrf.SidecarTableIDBase + 21},
			{vrf: "GtestvrfbV", pod: "podB", peer: "hostB", table: vrf.SidecarTableIDBase + 22},
		}
		for _, l := range links {
			if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: l.vrf}, Table: l.table}); err != nil {
				return err
			}
			vl, err := netlink.LinkByName(l.vrf)
			if err != nil {
				return err
			}
			if err := netlink.LinkSetUp(vl); err != nil {
				return err
			}
			// The peer stands in for the host end, which is in the host's
			// namespace in production.
			if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: l.pod}, PeerName: l.peer}); err != nil {
				return err
			}
			p, err := netlink.LinkByName(l.peer)
			if err != nil {
				return err
			}
			if err := netlink.LinkSetUp(p); err != nil {
				return err
			}
		}

		if err := configurePodLink("GmissingV", "podA", []netip.Addr{gw}, hostLL, nil); !errors.Is(err, errVRFMissing) {
			t.Errorf("configure without the VRF = %v, want errVRFMissing", err)
		}

		for _, l := range links {
			if err := configurePodLink(l.vrf, l.pod, []netip.Addr{gw}, hostLL, []netip.Addr{backend, other}); err != nil {
				return err
			}
			// Idempotent.
			if err := configurePodLink(l.vrf, l.pod, []netip.Addr{gw}, hostLL, []netip.Addr{backend, other}); err != nil {
				return err
			}
		}
		for _, l := range links {
			checkConfiguredLink(t, l.vrf, l.pod, l.table, gw, hostLL, backend)
		}
		checkLocalRouteHealed(t, links[1].vrf, links[1].pod, links[1].table, gw, hostLL, []netip.Addr{backend, other})

		// VPC A's second backend moves off-node: only its route goes, and
		// VPC B keeps both.
		if err := configurePodLink(links[0].vrf, links[0].pod, []netip.Addr{gw}, hostLL, []netip.Addr{backend}); err != nil {
			return err
		}
		if routes := localRoutes(t, links[0].table); len(routes) != 1 {
			t.Errorf("VPC A routes after the move = %v, want only %s", routes, backend)
		}
		if routes := localRoutes(t, links[1].table); len(routes) != 2 {
			t.Errorf("VPC B routes = %v, want both", routes)
		}

		// VPC A's proxy attachment changes its address: the old gateway goes.
		checkGatewayChange(t, links[0].vrf, links[0].pod, gw, hostLL, backend)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// checkGatewayChange reconfigures pod in vrfName with a new gateway address
// and checks that the old one, gw, is gone from it.
func checkGatewayChange(t *testing.T, vrfName, pod string, gw, hostLL, backend netip.Addr) {
	t.Helper()
	gw2 := netip.MustParseAddr("2001:db8:ff::2")
	if err := configurePodLink(vrfName, pod, []netip.Addr{gw2}, hostLL, []netip.Addr{backend}); err != nil {
		t.Fatal(err)
	}
	pl, err := netlink.LinkByName(pod)
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := netlink.AddrList(pl, netlink.FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if a.IP.Equal(gw.AsSlice()) {
			t.Errorf("%s keeps the old gateway %s", pod, gw)
		}
	}
}

// checkLocalRouteHealed replaces the gateway address on pod, which removes
// its local route from table as an older sidecar's every sweep did, and
// checks that the next configure restores the route.
func checkLocalRouteHealed(t *testing.T, vrfName, pod string, table uint32, gw, hostLL netip.Addr, local []netip.Addr) {
	t.Helper()
	pl, err := netlink.LinkByName(pod)
	if err != nil {
		t.Fatal(err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: gw.AsSlice(), Mask: net.CIDRMask(128, 128)}}
	if err := netlink.AddrReplace(pl, addr); err != nil {
		t.Fatal(err)
	}
	if err := configurePodLink(vrfName, pod, []netip.Addr{gw}, hostLL, local); err != nil {
		t.Fatal(err)
	}
	if ok, err := waitLocalRoute(table, pl.Attrs().Index, gw); err != nil || !ok {
		t.Errorf("table %d local route for %s on %s after the heal = %t, %v; want present", table, gw, pod, ok, err)
	}
}

// checkConfiguredLink checks that pod is up in vrfName, holds the gateway gw
// with its local route in table, and routes backend through pod to hostLL.
func checkConfiguredLink(t *testing.T, vrfName, pod string, table uint32, gw, hostLL, backend netip.Addr) {
	t.Helper()
	pl, err := netlink.LinkByName(pod)
	if err != nil {
		t.Fatal(err)
	}
	vl, err := netlink.LinkByName(vrfName)
	if err != nil {
		t.Fatal(err)
	}
	if pl.Attrs().MasterIndex != vl.Attrs().Index || pl.Attrs().Flags&net.FlagUp == 0 {
		t.Errorf("%s: master %d up %t, want %s and up", pod, pl.Attrs().MasterIndex,
			pl.Attrs().Flags&net.FlagUp != 0, vrfName)
	}
	if ok, err := hasAddr(pl, gw); err != nil || !ok {
		t.Errorf("%s has no gateway address %s (%v)", pod, gw, err)
	}
	// The second configure must not drop the gateway's local route, or the
	// pod resolves its own gateway as a neighbor.
	if ok, err := waitLocalRoute(table, pl.Attrs().Index, gw); err != nil || !ok {
		t.Errorf("table %d local route for %s on %s = %t, %v; want present", table, gw, pod, ok, err)
	}
	r, ok := localRoutes(t, table)[backend]
	if !ok || r.LinkIndex != pl.Attrs().Index || !r.Gw.Equal(hostLL.AsSlice()) {
		t.Errorf("table %d route to %s = %+v, want through %s to %s", table, backend, r, pod, hostLL)
	}
}

// TestConfigurePodLink_DefaultRouteSourcesTheGateway checks that connections
// to a backend on another node, which leave through the encapsulating egress
// veth, take the gateway as their source rather than the veth's link-local
// address, and that re-asserting the egress veth keeps that source.
func TestConfigurePodLink_DefaultRouteSourcesTheGateway(t *testing.T) {
	requireRoot(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	gw := netip.MustParseAddr("2001:db8:ff::1")
	hostLL := netip.MustParseAddr("fe80::1")
	const vrfName, table = "GtestvrfcV", vrf.SidecarTableIDBase + 23

	err = nsObj.Do(func(_ ns.NetNS) error {
		if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: vrfName}, Table: table}); err != nil {
			return err
		}
		vl, err := netlink.LinkByName(vrfName)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(vl); err != nil {
			return err
		}
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "podC"}, PeerName: "hostC"}); err != nil {
			return err
		}
		vrfLink := vl.(*netlink.Vrf)
		if _, err := ensureEgressVeth(vrfLink, "ivsC", "ivpC", 4000); err != nil {
			return err
		}
		if err := configurePodLink(vrfName, "podC", []netip.Addr{gw}, hostLL, nil); err != nil {
			return err
		}
		checkDefaultSource(t, table, gw, "after configure")
		// The sidecar re-asserts the egress datapath on every reapply.
		if _, err := ensureEgressVeth(vrfLink, "ivsC", "ivpC", 4000); err != nil {
			return err
		}
		checkDefaultSource(t, table, gw, "after the egress veth is re-asserted")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// checkDefaultSource checks that table's default route has src as its source.
func checkDefaultSource(t *testing.T, table uint32, src netip.Addr, when string) {
	t.Helper()
	r, err := vrfDefaultRoute(table)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil || !r.Src.Equal(src.AsSlice()) {
		t.Errorf("%s: table %d default route = %+v, want source %s", when, table, r, src)
	}
}

// waitLocalRoute waits up to 2s for table's local route for a on the link
// with index linkIdx. The kernel installs the local route of an address
// added with NODAD from its address configuration work, shortly after the
// add returns.
func waitLocalRoute(table uint32, linkIdx int, a netip.Addr) (bool, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		ok, err := hasLocalRoute(table, linkIdx, a)
		if err != nil || ok || time.Now().After(deadline) {
			return ok, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}
