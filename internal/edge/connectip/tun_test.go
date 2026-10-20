// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package connectip

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// requireRoot skips the test when not running as root. Creating a network
// namespace and a TUN device requires CAP_SYS_ADMIN and CAP_NET_ADMIN.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root (CAP_SYS_ADMIN, CAP_NET_ADMIN)")
	}
}

// newNetnsTUN creates a private network namespace holding TUN device cip0
// with testTarget/64 assigned, and returns the namespace and a TUNBackend for
// VPC blue on that device.
func newNetnsTUN(t *testing.T) (ns.NetNS, *TUNBackend) {
	t.Helper()
	netns, err := testutils.NewNS()
	if err != nil {
		t.Fatalf("create netns: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Close()
		_ = testutils.UnmountNS(netns)
	})

	var backend *TUNBackend
	err = netns.Do(func(ns.NetNS) error {
		var err error
		if backend, err = OpenTUN("cip0", vpcBlue); err != nil {
			return err
		}
		link, err := netlink.LinkByName("cip0")
		if err != nil {
			return err
		}
		addr := &netlink.Addr{
			IPNet: &net.IPNet{IP: net.IP(testTarget.AsSlice()), Mask: net.CIDRMask(64, 128)},
			Flags: unix.IFA_F_NODAD,
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	})
	if err != nil {
		t.Fatalf("set up TUN device: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return netns, backend
}

// TestTUNBackendReachesKernel tunnels an echo request through a TUN device
// into a private network namespace, where the kernel answers it.
func TestTUNBackendReachesKernel(t *testing.T) {
	requireRoot(t)
	_, backend := newNetnsTUN(t)

	env := startServer(t, func(c *Config) { c.Backend = backend })
	cc := newClientConn(t, env.dialQUIC(t))
	s := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))

	// The kernel originates the reply, so it carries the kernel's hop limit
	// less the proxy's decrement.
	reply := ping(t, s, 42, 256)
	if reply.hopLimit != 63 {
		t.Errorf("reply hop limit = %d, want 63", reply.hopLimit)
	}
	ping(t, s, 43, MinInnerMTU)

	other := SessionInfo{VPC: vpcGreen, Address: netip.MustParseAddr("fd00:a::102")}
	if _, err := backend.Open(context.Background(), other); err == nil {
		t.Error("TUN backend opened a session for another VPC")
	}
}
