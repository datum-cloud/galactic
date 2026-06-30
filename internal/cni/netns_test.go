// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"
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
