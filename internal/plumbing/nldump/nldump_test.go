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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/nldump"
	"go.datum.net/galactic/internal/plumbing/nldump/nldumptest"
)

// TestDumps_MatchPackageLevelFunctions pins that the retrying dumps run in the
// calling thread's network namespace and return what the package-level
// netlink functions return, including for a link deleted since it was looked
// up, which lists no addresses.
func TestDumps_MatchPackageLevelFunctions(t *testing.T) {
	requireRoot(t)
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

// TestLister_ListsTheHandlesNamespace pins that a Lister lists the network
// namespace its handle was opened in, not the calling thread's, and returns
// what the handle's own single-attempt methods return for every kind.
func TestLister_ListsTheHandlesNamespace(t *testing.T) {
	requireRoot(t)
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	// nsObj owns this descriptor. Its Path names the namespace of the thread
	// that created it, wherever that thread is now, so it cannot be opened
	// instead.
	h, err := netlink.NewHandleAt(netns.NsHandle(int(nsObj.Fd())))
	if err != nil {
		t.Fatalf("open handle in test netns: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "nldumplister"}}
	if err := h.LinkAdd(link); err != nil {
		t.Fatalf("add link: %v", err)
	}
	if err := h.LinkSetUp(link); err != nil {
		t.Fatalf("set link up: %v", err)
	}
	ip := net.ParseIP("fd00:2::1")
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}, Flags: unix.IFA_F_NODAD}
	if err := h.AddrAdd(link, addr); err != nil {
		t.Fatalf("add address: %v", err)
	}
	neighIP := net.ParseIP("fd00:2::2")
	if err := h.NeighAdd(&netlink.Neigh{
		LinkIndex: link.Attrs().Index, Family: netlink.FAMILY_V6, State: netlink.NUD_PERMANENT,
		IP: neighIP, HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
	}); err != nil {
		t.Fatalf("add neighbor: %v", err)
	}
	rule := netlink.NewRule()
	rule.Family, rule.Priority, rule.Table = netlink.FAMILY_V6, 1234, 1234
	if err := h.RuleAdd(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	l := nldump.On(h)
	links, err := l.LinkList()
	if err != nil {
		t.Fatalf("LinkList: %v", err)
	}
	if !strings.Contains(names(links), link.Name) {
		t.Errorf("LinkList = %s, want it to hold %s from the handle's namespace", names(links), link.Name)
	}
	host, err := nldump.LinkList()
	if err != nil {
		t.Fatalf("package LinkList: %v", err)
	}
	if strings.Contains(names(host), link.Name) {
		t.Errorf("package LinkList listed %s from another namespace", link.Name)
	}

	addrs, err := l.AddrList(link, netlink.FAMILY_V6)
	if err != nil || !slices.ContainsFunc(addrs, func(a netlink.Addr) bool { return a.IP.Equal(ip) }) {
		t.Errorf("AddrList = %v, %v; want it to hold %s", addrs, err, ip)
	}
	routes, err := l.RouteList(link, netlink.FAMILY_V6)
	wantRoutes, wantErr := h.RouteList(link, netlink.FAMILY_V6)
	if err != nil || wantErr != nil || len(routes) == 0 || len(routes) != len(wantRoutes) {
		t.Errorf("RouteList returned %d routes (%v), handle returned %d (%v); want equal and at least one",
			len(routes), err, len(wantRoutes), wantErr)
	}
	neighs, err := l.NeighList(link.Attrs().Index, netlink.FAMILY_V6)
	if err != nil || !slices.ContainsFunc(neighs, func(n netlink.Neigh) bool { return n.IP.Equal(neighIP) }) {
		t.Errorf("NeighList = %v, %v; want it to hold %s", neighs, err, neighIP)
	}
	rules, err := l.RuleList(netlink.FAMILY_V6)
	if err != nil || !slices.ContainsFunc(rules, func(r netlink.Rule) bool { return r.Priority == rule.Priority }) {
		t.Errorf("RuleList = %v, %v; want it to hold priority %d", rules, err, rule.Priority)
	}

	// The package-level forms list the calling thread's namespace, so each
	// must hold the objects this test made in it. Membership, not a count:
	// the kernel adds and removes its own entries on the link, the
	// all-routers multicast neighbor above all, between two dumps.
	err = nsObj.Do(func(ns.NetNS) error {
		got, err := nldump.NeighList(link.Attrs().Index, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("package NeighList: %w", err)
		}
		if !slices.ContainsFunc(got, func(n netlink.Neigh) bool { return n.IP.Equal(neighIP) }) {
			return fmt.Errorf("package NeighList = %v; want it to hold %s", got, neighIP)
		}
		gotRules, err := nldump.RuleList(netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("package RuleList: %w", err)
		}
		if !slices.ContainsFunc(gotRules, func(r netlink.Rule) bool { return r.Priority == rule.Priority }) {
			return fmt.Errorf("package RuleList = %v; want it to hold priority %d", gotRules, rule.Priority)
		}
		gotRoutes, err := nldump.RouteList(link, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("package RouteList: %w", err)
		}
		if !slices.ContainsFunc(gotRoutes, func(r netlink.Route) bool { return r.Dst != nil && r.Dst.Contains(ip) }) {
			return fmt.Errorf("package RouteList = %v; want it to hold a route for %s", gotRoutes, ip)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

// TestNldumptest_KindsMatchMetricLabels pins nldumptest's kind names to the
// label values the counters carry, so the helper never waits on a series
// that does not exist.
func TestNldumptest_KindsMatchMetricLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	nldump.MustRegister(reg)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	kinds := map[string]bool{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "kind" {
					kinds[l.GetValue()] = true
				}
			}
		}
	}
	for _, k := range []string{nldumptest.KindLink, nldumptest.KindAddress} {
		if !kinds[k] {
			t.Errorf("no counter carries kind %q; have %v", k, kinds)
		}
	}
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create a network namespace; re-run via sudo")
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
