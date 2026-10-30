// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostgw_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

const reenslaveVPC = "jU"

// reenslaveIPAM is the addressing ADD gives the test's tap: an IPv6 subnet
// with a gateway, and an IPv4 address with a gateway.
func reenslaveIPAM(t *testing.T) *cniipam.IPAMResult {
	t.Helper()
	_, sub6, err := net.ParseCIDR("2001:db8:1263::100/120")
	if err != nil {
		t.Fatal(err)
	}
	return &cniipam.IPAMResult{
		IPv6Subnet: sub6, IPv6Gateway: net.ParseIP("2001:db8:1263::1"),
		IPv4Address: net.ParseIP("192.0.2.10"), IPv4Gateway: net.ParseIP("192.0.2.1"),
	}
}

// inNetNS runs fn in a scratch network namespace with loopback up.
func inNetNS(t *testing.T, fn func() error) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root")
	}
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	if err := nsObj.Do(func(ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(lo); err != nil {
			return err
		}
		return fn()
	}); err != nil {
		t.Fatal(err)
	}
}

// addAttachment creates the VPC's VRF and an enslaved tap for att with the
// host gateway configured, as a tap ADD leaves them.
func addAttachment(t *testing.T, att string) {
	t.Helper()
	if err := vrf.EnsureAndEnslave(reenslaveVPC, func(*netlink.Vrf) error {
		_, err := tap.Add(reenslaveVPC, att, "c-"+att, 1400)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := hostgw.ConfigureHostGateway(reenslaveVPC, att, reenslaveIPAM(t), nil); err != nil {
		t.Fatal(err)
	}
}

// strandAttachment replays issue 1263 on att's tap: the VRF is deleted under
// it, recreated by a later ADD, and the tap's in-flight ADD then configures
// its host gateway, which lands the tap's addresses in the main table while
// the new VRF's table routes the guest's prefix to the masterless tap.
func strandAttachment(t *testing.T, att string) {
	t.Helper()
	if err := vrf.Delete(reenslaveVPC); err != nil {
		t.Fatal(err)
	}
	if err := vrf.Add(reenslaveVPC); err != nil {
		t.Fatal(err)
	}
	if err := hostgw.ConfigureHostGateway(reenslaveVPC, att, reenslaveIPAM(t), nil); err != nil {
		t.Fatal(err)
	}
	link := hostLink(t, att)
	if link.Attrs().MasterIndex != 0 {
		t.Fatalf("stranded tap has master %d, want none", link.Attrs().MasterIndex)
	}
	if len(routesOn(t, link, unix.RT_TABLE_MAIN)) == 0 {
		t.Fatal("stranded tap has no routes in the main table")
	}
}

func hostLink(t *testing.T, att string) netlink.Link {
	t.Helper()
	link, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(reenslaveVPC, att))
	if err != nil {
		t.Fatal(err)
	}
	return link
}

func vrfLink(t *testing.T) *netlink.Vrf {
	t.Helper()
	link, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(reenslaveVPC))
	if err != nil {
		t.Fatal(err)
	}
	return link.(*netlink.Vrf)
}

// routesOn returns the destinations of the routes through link in table.
func routesOn(t *testing.T, link netlink.Link, table int) map[string]bool {
	t.Helper()
	dsts := map[string]bool{}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family,
			&netlink.Route{LinkIndex: link.Attrs().Index, Table: table}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range routes {
			if r.Dst != nil {
				dsts[r.Dst.String()] = true
			}
		}
	}
	return dsts
}

// TestReenslaveRestoresStrandedTap strands an up tap the way issue 1263
// describes and runs the repair. The tap is enslaved to the VRF again and
// still up, its addresses are back, and its routes, connected, local and
// the guest's prefix, are in the VRF's table and none in the main table.
func TestReenslaveRestoresStrandedTap(t *testing.T) {
	inNetNS(t, func() error {
		addAttachment(t, "a1")
		strandAttachment(t, "a1")

		res, err := hostgw.ReenslaveMasterlessHostLinks()
		if err != nil {
			return err
		}
		if res.Reenslaved != 1 || res.Masterless != 0 || !res.Complete {
			return fmt.Errorf("result = %+v, want a complete pass with one re-enslaved and none left", res)
		}

		link, v := hostLink(t, "a1"), vrfLink(t)
		if link.Attrs().MasterIndex != v.Index {
			return fmt.Errorf("tap master = %d, want VRF %d", link.Attrs().MasterIndex, v.Index)
		}
		if link.Attrs().Flags&net.FlagUp == 0 {
			return errors.New("tap is down after repair, want it up")
		}
		for _, want := range []string{"2001:db8:1263::1/128", "192.0.2.1/25"} {
			found := false
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				addrs, err := netlink.AddrList(link, family)
				if err != nil {
					return err
				}
				for _, a := range addrs {
					found = found || a.IPNet.String() == want
				}
			}
			if !found {
				return fmt.Errorf("address %s missing after repair", want)
			}
		}
		inVRF := routesOn(t, link, int(v.Table))
		for _, want := range []string{"2001:db8:1263::100/120", "192.0.2.10/32", "2001:db8:1263::1/128", "192.0.2.1/32"} {
			if !inVRF[want] {
				return fmt.Errorf("route %s missing from VRF table %d after repair; have %v", want, v.Table, inVRF)
			}
		}
		if inMain := routesOn(t, link, unix.RT_TABLE_MAIN); len(inMain) != 0 {
			return fmt.Errorf("routes through the tap left in the main table: %v", inMain)
		}

		// A second pass finds nothing to do.
		res, err = hostgw.ReenslaveMasterlessHostLinks()
		if err != nil || res != (hostgw.MasterlessResult{Complete: true}) {
			return fmt.Errorf("second pass = %+v, %w; want nothing to do", res, err)
		}
		return nil
	})
}

// TestReenslaveKeepsDownTapDown re-enslaves a masterless tap that is down,
// as one quarantined for traffic policy is: it stays down.
func TestReenslaveKeepsDownTapDown(t *testing.T) {
	inNetNS(t, func() error {
		addAttachment(t, "a1")
		if err := netlink.LinkSetDown(hostLink(t, "a1")); err != nil {
			return err
		}
		if err := netlink.LinkSetNoMaster(hostLink(t, "a1")); err != nil {
			return err
		}

		res, err := hostgw.ReenslaveMasterlessHostLinks()
		if err != nil {
			return err
		}
		if res.Reenslaved != 1 {
			return fmt.Errorf("result = %+v, want one re-enslaved", res)
		}
		link := hostLink(t, "a1")
		if link.Attrs().MasterIndex != vrfLink(t).Index {
			return fmt.Errorf("tap master = %d, want the VRF", link.Attrs().MasterIndex)
		}
		if link.Attrs().Flags&net.FlagUp != 0 {
			return errors.New("quarantined tap came up during repair")
		}
		return nil
	})
}

// TestReenslaveCountsTapWithoutVRF leaves a masterless tap whose VPC has no
// VRF: the pass counts it and changes nothing.
func TestReenslaveCountsTapWithoutVRF(t *testing.T) {
	inNetNS(t, func() error {
		addAttachment(t, "a1")
		if err := vrf.Delete(reenslaveVPC); err != nil {
			return err
		}

		res, err := hostgw.ReenslaveMasterlessHostLinks()
		if err != nil {
			return err
		}
		if res.Reenslaved != 0 || res.Masterless != 1 {
			return fmt.Errorf("result = %+v, want one masterless and none re-enslaved", res)
		}
		if err := vrf.Exists(reenslaveVPC); err == nil {
			return errors.New("the repair created a VRF")
		}
		return nil
	})
}
