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
		if backend, err = openTestTUN("cip0", vpcBlue); err != nil {
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

	other := SessionInfo{VPC: vpcGreen, Prefix: firstPrefix}
	if _, err := backend.Open(context.Background(), other); err == nil {
		t.Error("TUN backend opened a session for another VPC")
	}
}

func openTestTUN(name, vpc string) (*TUNBackend, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return NewTUNBackend(os.NewFile(uintptr(fd), "/dev/net/tun"), vpc)
}

// TestTUNPrefixDemultiplexing uses a datagram descriptor to exercise backend
// dispatch without host privileges; the netns test separately proves TUN I/O.
func TestTUNPrefixDemultiplexing(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev := os.NewFile(uintptr(fds[0]), "backend")
	peer := os.NewFile(uintptr(fds[1]), "peer")
	defer func() { _ = peer.Close() }()
	backend, err := NewTUNBackend(dev, vpcBlue)
	if err != nil {
		_ = dev.Close()
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	info := SessionInfo{VPC: vpcBlue, Prefix: firstPrefix}
	first, err := backend.Open(t.Context(), info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Open(t.Context(), info); err == nil {
		t.Fatal("duplicate prefix accepted")
	}
	for _, addr := range []string{"fd00:a::1:0:1", "fd00:a::1:1234:5678", "fd00:a::1:ffff:ffff"} {
		dst := netip.MustParseAddr(addr)
		pkt := echoRequest(t, testTarget, dst, 1, 128)
		if _, err := peer.Write(pkt); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
		buf := make([]byte, maxPacketSize)
		n, err := first.ReadPacket(ctx, buf)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if got := parseICMPv6(t, buf[:n]); got.dst != dst {
			t.Fatalf("destination = %s, want %s", got.dst, dst)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := backend.Open(t.Context(), info)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.WritePacket(echoRequest(t, firstClient, testTarget, 2, 128)); err == nil {
		t.Fatal("closed session wrote a packet")
	}
	pkt := echoRequest(t, testTarget, firstClient, 3, 128)
	if _, err := peer.Write(pkt); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	if _, err := replacement.ReadPacket(ctx, make([]byte, maxPacketSize)); err != nil {
		t.Fatal(err)
	}
}
