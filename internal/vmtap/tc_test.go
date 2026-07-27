// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"fmt"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// requireRoot skips the test when not running as root. tap and tc
// operations require CAP_NET_ADMIN/CAP_SYS_ADMIN — mirrors the pattern in
// internal/cni/netns_test.go and internal/cni/tap/tap_test.go.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root (CAP_NET_ADMIN/CAP_SYS_ADMIN)")
	}
}

// inTestNetns creates a fresh network namespace with a dummy "eth0" link
// standing in for Cilium's real interface, runs fn inside it, and tears the
// namespace down afterward. Isolating each test in its own netns keeps
// tap/tc state from leaking onto the host running the test.
func inTestNetns(t *testing.T, fn func()) {
	t.Helper()
	requireRoot(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer nsObj.Close() //nolint:errcheck // best-effort cleanup

	err = nsObj.Do(func(_ ns.NetNS) error {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}
		if err := netlink.LinkAdd(dummy); err != nil {
			return fmt.Errorf("add dummy eth0: %w", err)
		}
		link, err := netlink.LinkByName("eth0")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("set eth0 up: %w", err)
		}
		fn()
		return nil
	})
	if err != nil {
		t.Fatalf("in test netns: %v", err)
	}
}

func TestAddTapCreatesLink(t *testing.T) {
	inTestNetns(t, func() {
		link, err := addTap("tap0", 1500, 0, 0)
		if err != nil {
			t.Fatalf("addTap() = %v, want nil", err)
		}
		if link.Type() != "tuntap" && link.Attrs().Name != "tap0" {
			t.Errorf("addTap() link = %+v, want a tap0 link", link.Attrs())
		}
		if link.Attrs().MTU != 1500 {
			t.Errorf("MTU = %d, want 1500", link.Attrs().MTU)
		}
	})
}

func TestAddTapIdempotent(t *testing.T) {
	inTestNetns(t, func() {
		if _, err := addTap("tap0", 1500, 0, 0); err != nil {
			t.Fatalf("first addTap() = %v, want nil", err)
		}
		if _, err := addTap("tap0", 1500, 0, 0); err != nil {
			t.Fatalf("second addTap() = %v, want nil (idempotent)", err)
		}
	})
}

func TestDeleteTapRemovesLink(t *testing.T) {
	inTestNetns(t, func() {
		if _, err := addTap("tap0", 1500, 0, 0); err != nil {
			t.Fatalf("addTap() = %v, want nil", err)
		}
		if err := deleteTap("tap0"); err != nil {
			t.Fatalf("deleteTap() = %v, want nil", err)
		}
		if _, err := netlink.LinkByName("tap0"); err == nil {
			t.Error("tap0 still exists after deleteTap")
		}
	})
}

func TestDeleteTapNonExistentIsNoop(t *testing.T) {
	inTestNetns(t, func() {
		if err := deleteTap("zzz-nonexistent"); err != nil {
			t.Errorf("deleteTap(nonexistent) = %v, want nil", err)
		}
	})
}

func TestAddRedirectAndCheck(t *testing.T) {
	inTestNetns(t, func() {
		tapLink, err := addTap("tap0", 1500, 0, 0)
		if err != nil {
			t.Fatalf("addTap() = %v, want nil", err)
		}
		eth0, err := netlink.LinkByName("eth0")
		if err != nil {
			t.Fatalf("find eth0: %v", err)
		}

		const priority = 7
		if err := addRedirect(eth0, tapLink, priority); err != nil {
			t.Fatalf("addRedirect(eth0->tap0) = %v, want nil", err)
		}
		if err := addRedirect(tapLink, eth0, priority); err != nil {
			t.Fatalf("addRedirect(tap0->eth0) = %v, want nil", err)
		}

		if ok, err := hasRedirectFilter(eth0, priority); err != nil || !ok {
			t.Errorf("hasRedirectFilter(eth0) = %v, %v, want true, nil", ok, err)
		}
		if ok, err := hasRedirectFilter(tapLink, priority); err != nil || !ok {
			t.Errorf("hasRedirectFilter(tap0) = %v, %v, want true, nil", ok, err)
		}

		if err := deleteRedirect(eth0, priority); err != nil {
			t.Fatalf("deleteRedirect(eth0) = %v, want nil", err)
		}
		if ok, err := hasRedirectFilter(eth0, priority); err != nil || ok {
			t.Errorf("hasRedirectFilter(eth0) after delete = %v, %v, want false, nil", ok, err)
		}
	})
}

func TestAddRedirectIdempotent(t *testing.T) {
	inTestNetns(t, func() {
		tapLink, err := addTap("tap0", 1500, 0, 0)
		if err != nil {
			t.Fatalf("addTap() = %v, want nil", err)
		}
		eth0, err := netlink.LinkByName("eth0")
		if err != nil {
			t.Fatalf("find eth0: %v", err)
		}

		const priority = 3
		if err := addRedirect(eth0, tapLink, priority); err != nil {
			t.Fatalf("first addRedirect() = %v, want nil", err)
		}
		if err := addRedirect(eth0, tapLink, priority); err != nil {
			t.Fatalf("second addRedirect() = %v, want nil (idempotent)", err)
		}

		filters, err := netlink.FilterList(eth0, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			t.Fatalf("FilterList() = %v, want nil", err)
		}
		count := 0
		for _, f := range filters {
			if f.Attrs().Priority == priority {
				count++
			}
		}
		if count != 1 {
			t.Errorf("filter count at priority %d = %d, want 1 (no duplicate)", priority, count)
		}
	})
}
