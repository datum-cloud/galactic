// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package radv

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// requireRoot skips the test when not running as root. Run as root, or inside
// an unprivileged user and network namespace (unshare -rn go test ...), which
// keeps the test's links off the host.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root")
	}
}

// testLinkLocal is the address addLinkLocalLink puts on its link.
var testLinkLocal = net.ParseIP("fe80::1")

// addLinkLocalLink creates an up dummy link called name carrying testLinkLocal
// with duplicate address detection skipped, and no kernel-generated
// link-local address that could still be tentative. It returns the link's
// index.
func addLinkLocalLink(t *testing.T, name string) int {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		t.Fatalf("create link %q: %v", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("look up link %q: %v", name, err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(name); err == nil && l.Attrs().Index == link.Attrs().Index {
			_ = netlink.LinkDel(l)
		}
	})
	if err := netlink.LinkSetIP6AddrGenMode(link, nl.IN6_ADDR_GEN_MODE_NONE); err != nil {
		t.Fatalf("disable address generation on %q: %v", name, err)
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: testLinkLocal, Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("add %s to %q: %v", testLinkLocal, name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("set %q up: %v", name, err)
	}
	return link.Attrs().Index
}

// openAndAdvertise does what RunActor does to start: look the interface up by
// name, open the NDP connection, join all-routers and send an advertisement.
func openAndAdvertise(t *testing.T, name string) error {
	t.Helper()
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up interface %q: %v", name, err)
	}
	conn, err := listen(ifi)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.JoinGroup(allRoutersMulticast); err != nil {
		return err
	}
	return conn.WriteTo(buildAdvertisement(1500, ifi.HardwareAddr), nil, allNodesMulticast)
}

// TestListenOnRecreatedInterface covers #1293: a tap deleted and recreated
// under the same name gets a new index, but the net package's name-to-index
// zone cache keeps the old one for up to a minute. Binding or sending with the
// interface name as the IPv6 zone then targets the deleted interface and fails
// with ENODEV until the cache expires, leaving the guest without a default
// route. Starting on the recreated interface must work at once.
func TestListenOnRecreatedInterface(t *testing.T) {
	requireRoot(t)

	const name = "radvtest0"
	first := addLinkLocalLink(t, name)
	// Prime the zone cache with the first link's index, as the actor that
	// served the previous guest did.
	if err := openAndAdvertise(t, name); err != nil {
		t.Fatalf("advertise on original link: %v", err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("look up link %q: %v", name, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		t.Fatalf("delete link %q: %v", name, err)
	}
	if second := addLinkLocalLink(t, name); second == first {
		t.Fatalf("recreated link kept index %d, cannot exercise a stale zone cache", first)
	}

	if err := openAndAdvertise(t, name); err != nil {
		t.Fatalf("advertise on recreated link: %v", err)
	}

	// The actor itself starts at once too: it returns nil only on a clean
	// cancellation after its connection was open.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := RunActor(ctx, name, 1500); err != nil {
		t.Fatalf("RunActor on recreated link: %v", err)
	}
}
