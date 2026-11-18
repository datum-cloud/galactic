// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ownership

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root (CAP_SYS_ADMIN, CAP_NET_ADMIN)")
	}
}

// TestStaleWriterCannotOverwriteAdoptedRoute applies the barrier to real
// kernel state: a route in a VRF-style table that an old writer prepared to
// replace while it still owned the scope. After the new owner adopts the
// scope and installs its own route, the old writer's resumed commit is
// refused and the new owner's route survives.
func TestStaleWriterCannotOverwriteAdoptedRoute(t *testing.T) {
	requireRoot(t)
	netns, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netns.Close()
		_ = testutils.UnmountNS(netns)
	})
	const table = 100
	dst := &net.IPNet{IP: net.ParseIP("fd00:5::"), Mask: net.CIDRMask(48, 128)}
	var oldLink, newLink int
	setRoute := func(link int) func() error {
		return func() error {
			return netns.Do(func(ns.NetNS) error {
				return netlink.RouteReplace(&netlink.Route{LinkIndex: link, Table: table, Dst: dst})
			})
		}
	}
	if err := netns.Do(func(ns.NetNS) error {
		for i, name := range []string{"old0", "new0"} {
			d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
			if err := netlink.LinkAdd(d); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(d); err != nil {
				return err
			}
			l, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			if i == 0 {
				oldLink = l.Attrs().Index
			} else {
				newLink = l.Attrs().Index
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	a := newAuthority(t)
	tk, err := a.Claim(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CommitSnapshot(tk, setRoute(oldLink)); err != nil {
		t.Fatal(err)
	}
	paused, err := a.Begin(scope, "cni")
	if err != nil {
		t.Fatal(err)
	}
	gen, err := a.Fence(scope)
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := a.Adopt(scope, "attachment-authority", gen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CommitSnapshot(adopted, setRoute(newLink)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Commit(paused, setRoute(oldLink)); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("resumed stale write = %v, want ErrNotOwner", err)
	}
	if err := netns.Do(func(ns.NetNS) error {
		routes, err := netlink.RouteListFiltered(unix.AF_INET6,
			&netlink.Route{Table: table, Dst: dst}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
		if err != nil {
			return err
		}
		if len(routes) != 1 || routes[0].LinkIndex != newLink {
			t.Errorf("routes for %s after the stale write = %+v, want only the adopter's via ifindex %d", dst, routes, newLink)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestStaleWriterCannotUndoMaintenance applies an exclusive write to real
// kernel state: the owner prepared to restore a route, then garbage
// collection removed it under the scope's lock. The owner's resumed commit
// is refused, and the route stays removed until the owner reads the state
// again.
func TestStaleWriterCannotUndoMaintenance(t *testing.T) {
	requireRoot(t)
	netns, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netns.Close()
		_ = testutils.UnmountNS(netns)
	})
	const table = 100
	dst := &net.IPNet{IP: net.ParseIP("fd00:6::"), Mask: net.CIDRMask(48, 128)}
	var link int
	route := func() *netlink.Route { return &netlink.Route{LinkIndex: link, Table: table, Dst: dst} }
	if err := netns.Do(func(ns.NetNS) error {
		d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "owner0"}}
		if err := netlink.LinkAdd(d); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(d); err != nil {
			return err
		}
		l, err := netlink.LinkByName("owner0")
		if err != nil {
			return err
		}
		link = l.Attrs().Index
		return netlink.RouteReplace(route())
	}); err != nil {
		t.Fatal(err)
	}

	a := newAuthority(t)
	tk, err := a.Claim(scope, "galactic-edge/1")
	if err != nil {
		t.Fatal(err)
	}
	if tk, err = a.CommitSnapshot(tk, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := a.Exclusive(scope, noCheck, func() error {
		return netns.Do(func(ns.NetNS) error { return netlink.RouteDel(route()) })
	}); err != nil {
		t.Fatal(err)
	}
	restore := func() error {
		return netns.Do(func(ns.NetNS) error { return netlink.RouteReplace(route()) })
	}
	if _, err := a.Commit(tk, restore); !errors.Is(err, ErrStale) {
		t.Fatalf("resumed stale write = %v, want ErrStale", err)
	}
	if err := netns.Do(func(ns.NetNS) error {
		routes, err := netlink.RouteListFiltered(unix.AF_INET6,
			&netlink.Route{Table: table, Dst: dst}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
		if err != nil {
			return err
		}
		if len(routes) != 0 {
			t.Errorf("routes for %s after the stale write = %+v, want none", dst, routes)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
