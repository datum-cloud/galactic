// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// requireRoot skips the test when not running as root.
// Network namespace operations (unshare, veth creation) require CAP_SYS_ADMIN.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root (CAP_SYS_ADMIN)")
	}
}

// createTestNetnsWithDummy creates a temporary network namespace, creates a
// dummy interface inside it, and returns the netns path and a cleanup function.
func createTestNetnsWithDummy(t *testing.T) (netnsPath string, cleanup func()) {
	t.Helper()

	requireRoot(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create new netns: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // best-effort cleanup

		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{Name: "test-dummy"},
		}
		if err := handle.LinkAdd(dummy); err != nil {
			return fmt.Errorf("add dummy link: %w", err)
		}
		if err := handle.LinkSetUp(dummy); err != nil {
			return fmt.Errorf("set dummy link up: %w", err)
		}
		return nil
	})
	if err != nil {
		nsObj.Close() //nolint:errcheck // best-effort cleanup
		t.Fatalf("setup dummy interface: %v", err)
	}

	cleanup = func() {
		_ = nsObj.Do(func(_ ns.NetNS) error {
			handle, err := netlink.NewHandle()
			if err != nil {
				return err
			}
			defer handle.Close() //nolint:errcheck // best-effort cleanup
			link, err := handle.LinkByName("test-dummy")
			if err != nil {
				return nil // already gone
			}
			return handle.LinkDel(link)
		})
		nsObj.Close() //nolint:errcheck // best-effort cleanup
	}

	return nsObj.Path(), cleanup
}

func TestCleanupContainerNetnsNonVeth(t *testing.T) {
	requireRoot(t)

	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	err := cleanupContainerNetns(netnsPath, "test-dummy")
	if err == nil {
		t.Fatal("expected error for non-veth interface, got nil")
	}
	if !strings.Contains(err.Error(), "is not a veth") {
		t.Fatalf("error %q does not contain 'is not a veth'", err.Error())
	}
	if !strings.Contains(err.Error(), "test-dummy") {
		t.Fatalf("error %q does not contain interface name 'test-dummy'", err.Error())
	}
}

func TestCleanupContainerNetnsNonExistent(t *testing.T) {
	requireRoot(t)

	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	// Cleanup a non-existent interface should return nil (idempotent).
	err := cleanupContainerNetns(netnsPath, "does-not-exist")
	if err != nil {
		t.Fatalf("expected nil for non-existent interface, got: %v", err)
	}
}

func TestCleanupContainerNetnsVeth(t *testing.T) {
	requireRoot(t)

	// Create a temporary network namespace with a veth pair.
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create new netns: %v", err)
	}
	defer nsObj.Close() //nolint:errcheck // best-effort cleanup

	// Create a veth pair: one end in the new namespace ("test-veth"),
	// the other end in the host namespace ("test-veth-peer").
	hostVethName := "test-veth-host"
	guestVethName := "test-veth"

	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // best-effort cleanup

		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: guestVethName},
			PeerName:  hostVethName,
		}
		if err := handle.LinkAdd(veth); err != nil {
			return fmt.Errorf("add veth link: %w", err)
		}
		if err := handle.LinkSetUp(veth); err != nil {
			return fmt.Errorf("set veth up: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup veth pair: %v", err)
	}

	// Verify the peer exists in host namespace.
	hostHandle, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("create host netlink handle: %v", err)
	}
	defer hostHandle.Close() //nolint:errcheck // best-effort cleanup

	_, err = hostHandle.LinkByName(hostVethName)
	if err != nil {
		t.Fatalf("veth peer %q not found in host ns: %v", hostVethName, err)
	}

	// Now call cleanupContainerNetns — it should succeed and delete the veth.
	err = cleanupContainerNetns(nsObj.Path(), guestVethName)
	if err != nil {
		t.Fatalf("cleanupContainerNetns(veth) returned error: %v", err)
	}

	// Verify the veth is gone from the container namespace.
	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // best-effort cleanup
		_, err = handle.LinkByName(guestVethName)
		if err == nil {
			return fmt.Errorf("interface %q still exists after cleanup", guestVethName)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the host-side peer still exists (only guest veth was deleted).
	_, err = hostHandle.LinkByName(hostVethName)
	if err != nil {
		t.Fatalf("veth peer %q was unexpectedly deleted from host ns: %v", hostVethName, err)
	}

	// Clean up the host-side peer.
	peer, _ := hostHandle.LinkByName(hostVethName)
	if peer != nil {
		_ = hostHandle.LinkDel(peer) //nolint:errcheck // best-effort cleanup
	}
}

// ---- addAddrAndDefaultRoute idempotency -------------------------------------

// testGateway/testIPNet mirror the environment described in the bug report:
// an IPv6-only attachment with a /48-style pool and a single default route
// per attachment/gateway.
var (
	testGateway = net.ParseIP("fd00:30:ff01::1")
	testIPNet   = &net.IPNet{IP: net.ParseIP("fd00:30:ff01::2"), Mask: net.CIDRMask(96, 128)}
)

// defaultRouteVia returns the gateway of the default route on "test-dummy"
// inside netnsPath, or nil if no default route is present. Fails the test on
// any other error.
func defaultRouteVia(t *testing.T, netnsPath string) net.IP {
	t.Helper()

	nsObj, err := ns.GetNS(netnsPath)
	if err != nil {
		t.Fatalf("open netns %q: %v", netnsPath, err)
	}
	defer nsObj.Close() //nolint:errcheck // best-effort cleanup

	var gw net.IP
	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName("test-dummy")
		if err != nil {
			return fmt.Errorf("find interface %q: %w", "test-dummy", err)
		}
		routes, err := handle.RouteList(link, netlink.FAMILY_V6)
		if err != nil {
			return err
		}
		for _, r := range routes {
			if isDefaultRouteDst(r.Dst) {
				gw = r.Gw
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read default route on test-dummy: %v", err)
	}
	return gw
}

// TestConfigureInterfaceInNetnsCleanAdd verifies a clean ADD installs the
// expected address and default route on a fresh netns/interface.
func TestConfigureInterfaceInNetnsCleanAdd(t *testing.T) {
	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("configureInterfaceInNetns: %v", err)
	}

	gw := defaultRouteVia(t, netnsPath)
	if gw == nil || !gw.Equal(testGateway) {
		t.Fatalf("default route gateway = %v, want %v", gw, testGateway)
	}
}

// TestConfigureInterfaceInNetnsAddTwiceIsIdempotent reproduces the reported
// bug: a caller that retries CNI ADD against the same netns without an
// intervening DEL (e.g. because an earlier ADD attempt was aborted before
// its own cleanup ran) must not see "file exists" on the second attempt.
func TestConfigureInterfaceInNetnsAddTwiceIsIdempotent(t *testing.T) {
	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("first configureInterfaceInNetns: %v", err)
	}
	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("second configureInterfaceInNetns (retry, no DEL in between): %v", err)
	}

	gw := defaultRouteVia(t, netnsPath)
	if gw == nil || !gw.Equal(testGateway) {
		t.Fatalf("default route gateway = %v, want %v", gw, testGateway)
	}
}

// TestConfigureInterfaceInNetnsAddAfterDel verifies that once the route is
// actually removed (what DEL achieves in production by moving the guest
// veth end out of the netns), a subsequent ADD on the same netns succeeds
// again rather than being permanently wedged.
func TestConfigureInterfaceInNetnsAddAfterDel(t *testing.T) {
	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("first configureInterfaceInNetns: %v", err)
	}

	// Simulate DEL: remove the address and route from the interface, the
	// same net effect host-device DEL's netns move has in production.
	nsObj, err := ns.GetNS(netnsPath)
	if err != nil {
		t.Fatalf("open netns %q: %v", netnsPath, err)
	}
	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName("test-dummy")
		if err != nil {
			return err
		}
		if err := handle.RouteDel(&netlink.Route{
			Gw: testGateway, LinkIndex: link.Attrs().Index, Flags: int(netlink.FLAG_ONLINK),
		}); err != nil {
			return fmt.Errorf("delete route: %w", err)
		}
		return handle.AddrDel(link, &netlink.Addr{IPNet: testIPNet})
	})
	nsObj.Close() //nolint:errcheck // best-effort cleanup
	if err != nil {
		t.Fatalf("simulate DEL: %v", err)
	}

	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("configureInterfaceInNetns after DEL: %v", err)
	}

	gw := defaultRouteVia(t, netnsPath)
	if gw == nil || !gw.Equal(testGateway) {
		t.Fatalf("default route gateway = %v, want %v", gw, testGateway)
	}
}

// TestConfigureInterfaceInNetnsConflictingGatewayErrors verifies that a
// pre-existing default route via a *different* gateway is a real
// misconfiguration and must still fail loudly rather than being papered
// over by the idempotency check.
func TestConfigureInterfaceInNetnsConflictingGatewayErrors(t *testing.T) {
	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	otherGateway := net.ParseIP("fd00:30:ff01::99")
	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, otherGateway, nil, nil); err != nil {
		t.Fatalf("install conflicting route: %v", err)
	}

	err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil)
	if err == nil {
		t.Fatal("expected error for conflicting default route gateway, got nil")
	}
	if !strings.Contains(err.Error(), "refusing to add conflicting route") {
		t.Fatalf("error %q does not mention refusing conflicting route", err.Error())
	}

	// The pre-existing (different) route must be left untouched.
	gw := defaultRouteVia(t, netnsPath)
	if gw == nil || !gw.Equal(otherGateway) {
		t.Fatalf("default route gateway = %v, want unchanged %v", gw, otherGateway)
	}
}

// ---- flushGuestNetnsConfig ---------------------------------------------

// TestFlushGuestNetnsConfigRemovesAddressAndRoute verifies that a configured
// address and default route are both removed, while the link itself
// survives (unlike cleanupContainerNetns, which deletes the whole
// interface).
func TestFlushGuestNetnsConfigRemovesAddressAndRoute(t *testing.T) {
	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("configureInterfaceInNetns: %v", err)
	}

	if err := flushGuestNetnsConfig(netnsPath, "test-dummy"); err != nil {
		t.Fatalf("flushGuestNetnsConfig: %v", err)
	}

	if gw := defaultRouteVia(t, netnsPath); gw != nil {
		t.Fatalf("default route gateway = %v, want nil (flushed)", gw)
	}

	nsObj, err := ns.GetNS(netnsPath)
	if err != nil {
		t.Fatalf("open netns %q: %v", netnsPath, err)
	}
	defer nsObj.Close() //nolint:errcheck // best-effort cleanup

	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

		link, err := handle.LinkByName("test-dummy")
		if err != nil {
			return fmt.Errorf("link should still exist after flush: %w", err)
		}
		addrs, err := handle.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return err
		}
		for _, a := range addrs {
			if a.Equal(netlink.Addr{IPNet: testIPNet}) {
				return fmt.Errorf("address %s still present after flush", testIPNet)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestFlushGuestNetnsConfigNonExistentInterface verifies the flush is a
// no-op (not an error) when the named interface isn't present — the case
// where host-device DEL never got as far as moving anything in.
func TestFlushGuestNetnsConfigNonExistentInterface(t *testing.T) {
	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	if err := flushGuestNetnsConfig(netnsPath, "does-not-exist"); err != nil {
		t.Fatalf("expected nil for non-existent interface, got: %v", err)
	}
}

// TestFlushGuestNetnsConfigThenRetryAddSucceeds reproduces the production
// incident: a hostNetwork pod's Multus secondary attachment resolves
// args.Netns to the same namespace the guest link already lives in, so
// host-device DEL's cross-namespace move — and the kernel's implicit
// address/route flush that comes with a *real* namespace change — never
// happens. Without an explicit flush, the leftover default route wedges the
// next ADD with "file exists" even though the link's own idempotency check
// (TestConfigureInterfaceInNetnsAddTwiceIsIdempotent) only covers a
// same-link retry, not one where cleanup ran in between but the flush
// silently no-opped.
func TestFlushGuestNetnsConfigThenRetryAddSucceeds(t *testing.T) {
	netnsPath, cleanup := createTestNetnsWithDummy(t)
	defer cleanup()

	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("first configureInterfaceInNetns: %v", err)
	}

	// Simulate DEL for the same-namespace (hostNetwork) case: the
	// move-based flush hostDevice DEL relies on doesn't fire, so DEL's only
	// effective cleanup is the explicit flush.
	if err := flushGuestNetnsConfig(netnsPath, "test-dummy"); err != nil {
		t.Fatalf("flushGuestNetnsConfig: %v", err)
	}

	// The retried ADD must now succeed against the same link.
	if err := configureInterfaceInNetns(netnsPath, "test-dummy", testIPNet, testGateway, nil, nil); err != nil {
		t.Fatalf("configureInterfaceInNetns after flush: %v", err)
	}

	gw := defaultRouteVia(t, netnsPath)
	if gw == nil || !gw.Equal(testGateway) {
		t.Fatalf("default route gateway = %v, want %v", gw, testGateway)
	}
}
