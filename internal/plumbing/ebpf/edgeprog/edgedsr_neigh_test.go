// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests cover a backend whose route resolves to a next hop with no
// neighbor entry, as on a gateway that has just rejoined the fabric. XDP
// cannot start neighbor resolution, so edge_lb hands the encapsulated packet
// to the kernel instead of dropping it.

// ipprotoIPv6Encap is the outer Next Header of an encapsulated IPv6 packet.
const ipprotoIPv6Encap = 41

var (
	// unresolvedLocal and unresolvedNextHop share the link the backend's
	// uSID is routed over; the gateway holds no neighbor entry for the next
	// hop. unresolvedLocal is also the gateway's encapsulation source.
	unresolvedLocal   = netip.MustParseAddr("fd00:5::1")
	unresolvedNextHop = netip.MustParseAddr("fd00:5::2")
)

// TestEdgeLB_UnresolvedNextHopGoesToKernel covers both VIP families through
// a test run: the packet leaves encapsulated, framed as it arrived, as
// XDP_PASS straight to the kernel rather than through the dispatcher's later
// slots, and counts as a fallback rather than a drop.
func TestEdgeLB_UnresolvedNextHopGoesToKernel(t *testing.T) {
	for _, tt := range []struct {
		name  string
		build func(t *testing.T, objs *EdgedsrObjects) (EdgedsrVipKey, []byte, int)
	}{
		{name: "IPv6 VIP", build: func(t *testing.T, objs *EdgedsrObjects) (EdgedsrVipKey, []byte, int) {
			vip := netip.MustParseAddr("2001:db8::100")
			// putIPv4VIP loads a VIP of either family; only its name is IPv4.
			key := putIPv4VIP(t, objs, ipprotoTCP, 443, vip, testUSID)
			pkt := buildL4Packet(t, ipprotoTCP, vip, netip.MustParseAddr("2001:db8:ffff::1"), 41000, 443, nil)
			return key, pkt, ipprotoIPv6Encap
		}},
		{name: "IPv4 VIP", build: func(t *testing.T, objs *EdgedsrObjects) (EdgedsrVipKey, []byte, int) {
			key := putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, testUSID)
			pkt := buildIPv4Packet(t, ipprotoTCP, testVIP4, testClient4, 41000, 443, nil, ip4Opts{})
			return key, pkt, ipprotoIPIP
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requireRoot(t)
			narrowFabric(t, fabricMTU)
			routeViaUnresolvedNextHop(t, testUSID)
			objs := loadObjects(t)
			installChainStub(t, objs, roleGatewayLB|roleEgress)
			key, pkt, nexthdr := tt.build(t, objs)

			ret, out := runLB(t, objs, pkt)
			if ret != xdpPass {
				t.Fatalf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
			}
			if len(out) < ethLen+ip6Len {
				t.Fatalf("output is %d bytes, too short for Ethernet and an outer IPv6 header", len(out))
			}
			if !bytes.Equal(out[:12], pkt[:12]) {
				t.Errorf("MAC addresses = % x, want the arriving frame's % x", out[:12], pkt[:12])
			}
			if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
				t.Errorf("EtherType = %#04x, want IPv6", got)
			}
			if got := out[ethLen+6]; got != byte(nexthdr) {
				t.Errorf("outer next header = %d, want %d", got, nexthdr)
			}
			if got := netip.AddrFrom16([16]byte(out[ethLen+24 : ethLen+40])); got != testUSID {
				t.Errorf("outer destination = %v, want the backend's uSID %v", got, testUSID)
			}
			if !bytes.Equal(out[ethLen+ip6Len:], pkt[ethLen:]) {
				t.Errorf("inner packet changed:\n got: % x\nwant: % x", out[ethLen+ip6Len:], pkt[ethLen:])
			}

			if got := sumPerCPU(t, objs.NeighFallbacks, 0); got != 1 {
				t.Errorf("neigh_fallbacks = %d, want 1", got)
			}
			if got := sumPerCPU(t, objs.DropReasons, DropReasonFibNoNeigh); got != 0 {
				t.Errorf("drop_reasons[fib_no_neigh] = %d, want 0", got)
			}
			var stats EdgedsrVipStatsValue
			if err := objs.VipStatsTable.Lookup(key, &stats); err != nil {
				t.Fatalf("lookup vip_stats_table: %v", err)
			}
			if stats.Packets != 1 || stats.DroppedPackets != 0 {
				t.Errorf("vip stats packets/dropped = %d/%d, want 1/0", stats.Packets, stats.DroppedPackets)
			}
		})
	}
}

// TestEdgeLB_KernelResolvesUnresolvedNextHop proves the fallback on a real
// kernel, which a test run cannot: with edge_lb attached to the uplink, the
// first packet to a backend behind an unresolved next hop reaches that next
// hop, and the neighbor entry the kernel resolved for it keeps the next packet
// in XDP.
func TestEdgeLB_KernelResolvesUnresolvedNextHop(t *testing.T) {
	requireRoot(t)
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("test requires /dev/net/tun: %v", err)
	}

	// The gateway's namespace holds the uplink tap, where client frames are
	// written, and one end of a veth pair whose other end, in the next hop's
	// namespace, holds unresolvedNextHop.
	runtime.LockOSThread()
	origNS := openThreadNetns(t)
	t.Cleanup(func() {
		if err := unix.Setns(origNS, unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore original network namespace: %v", err)
			return
		}
		_ = unix.Close(origNS)
		runtime.UnlockOSThread()
	})
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare gateway network namespace: %v", err)
	}
	gatewayNS := openThreadNetns(t)
	t.Cleanup(func() { _ = unix.Close(gatewayNS) })
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare next hop network namespace: %v", err)
	}
	nextHopNS := openThreadNetns(t)
	t.Cleanup(func() { _ = unix.Close(nextHopNS) })
	setNetns(t, gatewayNS)

	for _, path := range []string{"/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv6/conf/default/forwarding"} {
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
			t.Fatalf("enable forwarding via %s: %v", path, err)
		}
	}
	uplinkFd, uplink := openTap(t, "up0")

	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "nh0"}, PeerName: "nh1"}); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}
	peer, err := netlink.LinkByName("nh1")
	if err != nil {
		t.Fatalf("look up veth peer: %v", err)
	}
	if err := netlink.LinkSetNsFd(peer, nextHopNS); err != nil {
		t.Fatalf("move veth peer into the next hop's namespace: %v", err)
	}
	setNetns(t, nextHopNS)
	peer = setLinkUp(t, "nh1")
	addLinkAddr(t, peer, unresolvedNextHop, 64)
	capture := openCapture(t, peer.Attrs().Index)
	setNetns(t, gatewayNS)
	fabric := setLinkUp(t, "nh0")
	addLinkAddr(t, fabric, unresolvedLocal, 64)
	awaitLinkLocal(t, fabric.Attrs().Index)
	routeOver(t, fabric, testUSID, unresolvedNextHop)

	objs := loadObjects(t)
	vip := netip.MustParseAddr("2001:db8::100")
	putIPv4VIP(t, objs, ipprotoUDP, 443, vip, testUSID)
	if err := objs.EncapConfigTable.Put(uint32(0), EdgedsrEncapConfig{EncapSrc: unresolvedLocal.As16()}); err != nil {
		t.Fatalf("populate encap_config_table: %v", err)
	}
	xdp, err := link.AttachXDP(link.XDPOptions{Program: objs.EdgeLb, Interface: uplink.Attrs().Index})
	if err != nil {
		t.Fatalf("attach edge_lb to the uplink: %v", err)
	}
	t.Cleanup(func() { _ = xdp.Close() })

	send := func(label string) []byte {
		marker := fmt.Appendf(nil, "edge-neigh:%s:%d", label, time.Now().UnixNano())
		pkt := buildL4Packet(t, ipprotoUDP, vip, netip.MustParseAddr("2001:db8:ffff::1"), 41000, 443, marker)
		copy(pkt[0:6], uplink.Attrs().HardwareAddr)
		if _, err := unix.Write(uplinkFd, pkt); err != nil {
			t.Fatalf("write frame into the uplink tap: %v", err)
		}
		return marker
	}

	if neighborValid(t, fabric.Attrs().Index, unresolvedNextHop) {
		t.Fatalf("a neighbor entry for %v exists before the first packet, so nothing is left to resolve", unresolvedNextHop)
	}
	if !awaitMarker(t, capture, send("unresolved"), 2*time.Second) {
		t.Fatalf("the packet sent while the next hop was unresolved never reached it "+
			"(neigh_fallbacks=%d, fib_no_neigh=%d)",
			sumPerCPU(t, objs.NeighFallbacks, 0), sumPerCPU(t, objs.DropReasons, DropReasonFibNoNeigh))
	}
	if !neighborValid(t, fabric.Attrs().Index, unresolvedNextHop) {
		t.Fatalf("no valid neighbor entry for %v after the first packet, want one the kernel resolved", unresolvedNextHop)
	}
	if got := sumPerCPU(t, objs.NeighFallbacks, 0); got != 1 {
		t.Errorf("neigh_fallbacks after the first packet = %d, want 1", got)
	}

	// The second packet finds the neighbor and is redirected in XDP. Its
	// delivery over a veth depends on the peer's own XDP setup, so only the
	// counters are checked.
	send("resolved")
	if got := sumPerCPU(t, objs.NeighFallbacks, 0); got != 1 {
		t.Errorf("neigh_fallbacks after the second packet = %d, want 1: a resolved next hop stays in XDP", got)
	}
	for i := range DropReasonCount {
		if got := sumPerCPU(t, objs.DropReasons, i); got != 0 {
			t.Errorf("drop_reasons[%s] = %d, want 0", DropReasonNames[i], got)
		}
	}
}

// routeViaUnresolvedNextHop routes dst over a veth pair, in the current
// namespace, through unresolvedNextHop, for which no neighbor entry exists.
// A dummy link would not do: it needs no neighbor resolution at all.
func routeViaUnresolvedNextHop(t *testing.T, dst netip.Addr) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "nh0"}, PeerName: "nh1"}); err != nil {
		t.Fatalf("add veth pair: %v", err)
	}
	setLinkUp(t, "nh1")
	fabric := setLinkUp(t, "nh0")
	addLinkAddr(t, fabric, unresolvedLocal, 64)
	routeOver(t, fabric, dst, unresolvedNextHop)
}

func routeOver(t *testing.T, l netlink.Link, dst, via netip.Addr) {
	t.Helper()
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: l.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IP(dst.AsSlice()), Mask: net.CIDRMask(128, 128)},
		Gw:        net.IP(via.AsSlice()),
	}); err != nil {
		t.Fatalf("route %v via %v: %v", dst, via, err)
	}
}

// addLinkAddr assigns addr/bits to l, without duplicate address detection, so
// it can send and answer solicitations at once.
func addLinkAddr(t *testing.T, l netlink.Link, addr netip.Addr, bits int) {
	t.Helper()
	a := &netlink.Addr{
		IPNet: &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(bits, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(l, a); err != nil {
		t.Fatalf("address %s with %v: %v", l.Attrs().Name, addr, err)
	}
}

// awaitLinkLocal waits for the link's link-local address to leave duplicate
// address detection: the kernel solicits a neighbor only from a usable one.
func awaitLinkLocal(t *testing.T, ifindex int) {
	t.Helper()
	l := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: ifindex}}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
		if err != nil {
			t.Fatalf("list addresses on ifindex %d: %v", ifindex, err)
		}
		for _, a := range addrs {
			if a.IP.IsLinkLocalUnicast() && a.Flags&unix.IFA_F_TENTATIVE == 0 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("ifindex %d's link-local address was still tentative after 5s", ifindex)
}

func neighborValid(t *testing.T, ifindex int, dst netip.Addr) bool {
	t.Helper()
	neighs, err := netlink.NeighList(ifindex, netlink.FAMILY_V6)
	if err != nil {
		t.Fatalf("list neighbors on ifindex %d: %v", ifindex, err)
	}
	const valid = netlink.NUD_PERMANENT | netlink.NUD_NOARP | netlink.NUD_REACHABLE |
		netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE
	for _, n := range neighs {
		if n.IP.Equal(net.IP(dst.AsSlice())) && n.State&valid != 0 {
			return true
		}
	}
	return false
}

func openThreadNetns(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open thread network namespace: %v", err)
	}
	return fd
}

func setNetns(t *testing.T, fd int) {
	t.Helper()
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		t.Fatalf("setns: %v", err)
	}
}

// openTap creates a non-persistent tap owned by the returned descriptor and
// brings it up. Holding the descriptor open is what gives the tap carrier.
func openTap(t *testing.T, name string) (int, netlink.Link) {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("ifreq for %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("create tap %s: %v", name, err)
	}
	return fd, setLinkUp(t, name)
}

func setLinkUp(t *testing.T, name string) netlink.Link {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatalf("set %s up: %v", name, err)
	}
	if l, err = netlink.LinkByName(name); err != nil {
		t.Fatalf("re-read %s: %v", name, err)
	}
	return l
}

func openCapture(t *testing.T, ifindex int) int {
	t.Helper()
	proto := bswap16(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		t.Fatalf("open packet socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifindex}); err != nil {
		t.Fatalf("bind packet socket to ifindex %d: %v", ifindex, err)
	}
	return fd
}

// awaitMarker reports whether a frame containing marker arrives on the
// capture socket fd within wait, skipping unrelated frames such as neighbor
// discovery.
func awaitMarker(t *testing.T, fd int, marker []byte, wait time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(wait)
	buf := make([]byte, 65536)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, int(remaining.Milliseconds())+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("poll fd %d: %v", fd, err)
		}
		if ready == 0 {
			return false
		}
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("read fd %d: %v", fd, err)
		}
		if bytes.Contains(buf[:n], marker) {
			return true
		}
	}
}
