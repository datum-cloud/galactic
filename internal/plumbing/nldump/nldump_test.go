// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nldump_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/nldump"
)

// TestDumps_MatchPackageLevelFunctions pins that the retrying dumps run in the
// calling thread's network namespace and return what the package-level
// netlink functions return, including for a link deleted since it was looked
// up, which lists no addresses.
func TestDumps_MatchPackageLevelFunctions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create a network namespace; re-run via sudo")
	}
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	err = nsObj.Do(func(_ ns.NetNS) error {
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "nldumptest"}}
		if err := netlink.LinkAdd(link); err != nil {
			return fmt.Errorf("add link: %w", err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("set link up: %w", err)
		}
		addr := &netlink.Addr{
			IPNet: &net.IPNet{IP: net.ParseIP("fd00:1::1"), Mask: net.CIDRMask(64, 128)},
			Flags: unix.IFA_F_NODAD,
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("add address: %w", err)
		}

		links, err := nldump.LinkList()
		if err != nil {
			return fmt.Errorf("LinkList: %w", err)
		}
		want, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("netlink.LinkList: %w", err)
		}
		if names(links) != names(want) {
			t.Errorf("LinkList = %s, want %s", names(links), names(want))
		}

		addrs, err := nldump.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("AddrList: %w", err)
		}
		if !slices.ContainsFunc(addrs, func(a netlink.Addr) bool { return a.IP.Equal(addr.IP) }) {
			t.Errorf("AddrList = %v, want it to hold %s", addrs, addr.IP)
		}

		filter := &netlink.Route{Table: unix.RT_TABLE_MAIN, LinkIndex: link.Attrs().Index}
		mask := netlink.RT_FILTER_TABLE | netlink.RT_FILTER_OIF
		routes, err := nldump.RouteListFiltered(netlink.FAMILY_V6, filter, mask)
		if err != nil {
			return fmt.Errorf("RouteListFiltered: %w", err)
		}
		wantRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, filter, mask)
		if err != nil {
			return fmt.Errorf("netlink.RouteListFiltered: %w", err)
		}
		if len(routes) == 0 || len(routes) != len(wantRoutes) {
			t.Errorf("RouteListFiltered returned %d routes, want %d and at least one", len(routes), len(wantRoutes))
		}

		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("delete link: %w", err)
		}
		gone, err := nldump.AddrList(link, netlink.FAMILY_ALL)
		wantGone, wantErr := netlink.AddrList(link, netlink.FAMILY_ALL)
		if !errors.Is(err, wantErr) || len(gone) != len(wantGone) {
			t.Errorf("AddrList on a deleted link = %v, %v; netlink.AddrList = %v, %v", gone, err, wantGone, wantErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func names(links []netlink.Link) string {
	out := make([]string, 0, len(links))
	for _, l := range links {
		out = append(out, l.Attrs().Name)
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}
