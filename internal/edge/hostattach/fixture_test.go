// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/vrf"
)

// podEth0 is a pod's ordinary interface, standing in for its cluster
// networking.
const podEth0 = "eth0"

// requireRoot skips the test when not running as root. The fixture creates
// network namespaces, VRFs, veths and TUN devices.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root (CAP_SYS_ADMIN, CAP_NET_ADMIN)")
	}
}

// testNS is a fixture-owned network namespace bind-mounted at a stable path.
type testNS struct {
	ns.NetNS
}

func newTestNS(t *testing.T) testNS {
	t.Helper()
	n, err := testutils.NewNS()
	if err != nil {
		t.Fatalf("create network namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = n.Close()
		_ = testutils.UnmountNS(n)
	})
	return testNS{n}
}

func (n testNS) do(t *testing.T, fn func() error) {
	t.Helper()
	if err := n.Do(func(ns.NetNS) error { return fn() }); err != nil {
		t.Fatal(err)
	}
}

func (n testNS) open(t *testing.T) *Namespace {
	t.Helper()
	h, err := OpenNamespace(n.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func ip6Net(s string) *net.IPNet {
	p := netip.MustParsePrefix(s)
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 128)}
}

func addAddr(link netlink.Link, cidr string) error {
	return netlink.AddrReplace(link, &netlink.Addr{IPNet: ip6Net(cidr), Flags: unix.IFA_F_NODAD})
}

// newHost builds the node namespace: forwarding on, an uplink holding the
// main table's default route, standing in for the node's outer transport, and
// the canonical VRF of each VPC, created by the same code the CNI uses.
func newHost(t *testing.T, vpcs ...string) testNS {
	t.Helper()
	host := newTestNS(t)
	host.do(t, func() error {
		if err := enableSysctl("net/ipv6/conf/all/forwarding"); err != nil {
			return err
		}
		uplink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: uplinkName}}
		if err := netlink.LinkAdd(uplink); err != nil {
			return err
		}
		if err := addAddr(uplink, "2001:db8:ffff::1/64"); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(uplink); err != nil {
			return err
		}
		def := &netlink.Route{
			LinkIndex: uplink.Index, Dst: ip6Net("::/0"),
			Gw: net.ParseIP("2001:db8:ffff::fe"), Flags: int(netlink.FLAG_ONLINK),
		}
		if err := netlink.RouteAdd(def); err != nil {
			return fmt.Errorf("uplink default: %w", err)
		}
		for _, vpc := range vpcs {
			if err := vrf.Add(vpc); err != nil {
				return fmt.Errorf("canonical VRF for %s: %w", vpc, err)
			}
		}
		return nil
	})
	return host
}

// newWorkload creates an ordinary VPC workload: its own namespace with one
// address, attached directly to the canonical host VRF the way the CNI's veth
// plugin attaches a pod.
func newWorkload(t *testing.T, host testNS, hostVRF, hostLink, addr string) testNS {
	t.Helper()
	wl := newTestNS(t)
	var wlMAC, hostMAC net.HardwareAddr
	wl.do(t, func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: podEth0}, PeerName: hostLink,
			PeerNamespace: netlink.NsFd(int(host.Fd())),
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
		eth0, err := netlink.LinkByName(podEth0)
		if err != nil {
			return err
		}
		wlMAC = eth0.Attrs().HardwareAddr
		for _, a := range []string{addr + "/128", "fe80::2/64"} {
			if err := addAddr(eth0, a); err != nil {
				return err
			}
		}
		return netlink.LinkSetUp(eth0)
	})
	host.do(t, func() error {
		link, err := netlink.LinkByName(hostLink)
		if err != nil {
			return err
		}
		hostMAC = link.Attrs().HardwareAddr
		master, err := netlink.LinkByName(hostVRF)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetMaster(link, master); err != nil {
			return err
		}
		if err := addAddr(link, "fe80::1/64"); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		if err := netlink.NeighSet(&netlink.Neigh{
			LinkIndex: link.Attrs().Index, Family: unix.AF_INET6, State: netlink.NUD_PERMANENT,
			IP: net.ParseIP(addr), HardwareAddr: wlMAC,
		}); err != nil {
			return err
		}
		return netlink.RouteReplace(&netlink.Route{
			LinkIndex: link.Attrs().Index, Table: int(master.(*netlink.Vrf).Table),
			Scope: netlink.SCOPE_LINK, Dst: ip6Net(addr + "/128"),
		})
	})
	wl.do(t, func() error {
		eth0, err := netlink.LinkByName(podEth0)
		if err != nil {
			return err
		}
		if err := netlink.NeighSet(&netlink.Neigh{
			LinkIndex: eth0.Attrs().Index, Family: unix.AF_INET6, State: netlink.NUD_PERMANENT,
			IP: net.ParseIP("fe80::1"), HardwareAddr: hostMAC,
		}); err != nil {
			return err
		}
		return netlink.RouteReplace(&netlink.Route{
			LinkIndex: eth0.Attrs().Index, Dst: ip6Net("::/0"), Gw: net.ParseIP("fe80::1"),
		})
	})
	return wl
}

// newPod creates a consumer pod namespace with an eth0 on the node's main
// table and a default route through it, standing in for the pod's ordinary
// cluster networking. Tenant traffic must never leave through it.
func newPod(t *testing.T, host testNS, mgmtLink string, n int) testNS {
	t.Helper()
	pod := newTestNS(t)
	hostAddr := fmt.Sprintf("fd99:%d::1", n)
	pod.do(t, func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: podEth0}, PeerName: mgmtLink,
			PeerNamespace: netlink.NsFd(int(host.Fd())),
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
		eth0, err := netlink.LinkByName(podEth0)
		if err != nil {
			return err
		}
		if err := addAddr(eth0, fmt.Sprintf("fd99:%d::2/64", n)); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(eth0); err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{LinkIndex: eth0.Attrs().Index, Dst: ip6Net("::/0"), Gw: net.ParseIP(hostAddr)})
	})
	host.do(t, func() error {
		link, err := netlink.LinkByName(mgmtLink)
		if err != nil {
			return err
		}
		if err := addAddr(link, hostAddr+"/64"); err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	})
	return pod
}

// leakWatch counts IPv6 packets a link transmits toward one destination,
// directly or inside an encapsulating IPv6 header. Counting only those, rather
// than every transmitted packet, keeps the kernel's own neighbor discovery
// and multicast listener traffic from looking like a leak.
type leakWatch struct {
	fd    int
	dst   netip.Addr
	count atomic.Uint64
	done  chan struct{}
}

// watchLeaks starts capturing on link inside n. Call stop to end the capture
// and read the count.
func watchLeaks(t *testing.T, n testNS, link string, dst netip.Addr) *leakWatch {
	t.Helper()
	w := &leakWatch{dst: dst, done: make(chan struct{})}
	// Transmitted packets reach only ETH_P_ALL packet sockets, never ones
	// bound to a single protocol, so IPv6 is filtered in run instead.
	proto := int(htons(unix.ETH_P_ALL))
	n.do(t, func() error {
		l, err := netlink.LinkByName(link)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, proto)
		if err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: l.Attrs().Index}); err != nil {
			_ = unix.Close(fd)
			return err
		}
		tv := unix.Timeval{Usec: 50000}
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			_ = unix.Close(fd)
			return err
		}
		w.fd = fd
		return nil
	})
	go w.run()
	return w
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (w *leakWatch) run() {
	defer close(w.done)
	buf := make([]byte, 65536)
	for {
		n, from, err := unix.Recvfrom(w.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || ll.Pkttype != unix.PACKET_OUTGOING || ll.Protocol != htons(unix.ETH_P_IPV6) || n < 40 {
			continue
		}
		if w.matches(buf[:n]) {
			w.count.Add(1)
		}
	}
}

// matches reports whether pkt, or an IPv6 packet it encapsulates, is
// addressed to the watched destination.
func (w *leakWatch) matches(pkt []byte) bool {
	for len(pkt) >= 40 && pkt[0]>>4 == 6 {
		if dst, ok := netip.AddrFromSlice(pkt[24:40]); ok && dst == w.dst {
			return true
		}
		if pkt[6] != unix.IPPROTO_IPV6 {
			return false
		}
		pkt = pkt[40:]
	}
	return false
}

// stop ends the capture and returns how many matching packets left the link.
func (w *leakWatch) stop() uint64 {
	_ = unix.Shutdown(w.fd, unix.SHUT_RD)
	_ = unix.Close(w.fd)
	<-w.done
	return w.count.Load()
}

func bindToDevice(dev string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		if dev == "" {
			return nil
		}
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
		}); err != nil {
			return err
		}
		return sockErr
	}
}

// serveIdentity answers every TCP connection to port with ident. With dev
// set, the listener is bound to that VRF, as a socket-access consumer's are.
func serveIdentity(t *testing.T, n testNS, dev string, port int, ident string) {
	t.Helper()
	var ln net.Listener
	n.do(t, func() error {
		var err error
		lc := net.ListenConfig{Control: bindToDevice(dev)}
		ln, err = lc.Listen(context.Background(), "tcp6", fmt.Sprintf("[::]:%d", port))
		return err
	})
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, ident)
			_ = c.Close()
		}
	}()
}

// dialIdentity connects from inside n, bound to dev when set, and returns
// what the server sent.
func dialIdentity(n testNS, dev string, dst netip.AddrPort) (string, error) {
	var got string
	err := n.Do(func(ns.NetNS) error {
		d := net.Dialer{Timeout: 2 * time.Second, Control: bindToDevice(dev)}
		c, err := d.Dial("tcp6", dst.String())
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		b, err := io.ReadAll(c)
		got = string(b)
		return err
	})
	return got, err
}

var (
	errUnreachable = errors.New("destination unreachable")
	errNoReply     = errors.New("no echo reply")
)

// packetTooBigError is an ICMPv6 Packet Too Big answering a ping.
type packetTooBigError struct{ MTU int }

func (e *packetTooBigError) Error() string { return fmt.Sprintf("packet too big, MTU %d", e.MTU) }

var echoID atomic.Uint32

// ping sends one ICMPv6 echo request of size bytes, IPv6 header included,
// from inside n and waits for the reply. It returns errUnreachable or a
// *packetTooBigError if the matching ICMPv6 error comes back instead.
func ping(n testNS, dst netip.Addr, size int) error {
	return n.Do(func(ns.NetNS) error {
		var lc net.ListenConfig
		c, err := lc.ListenPacket(context.Background(), "ip6:ipv6-icmp", "::")
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		id := int(echoID.Add(1) & 0xffff)
		payload := make([]byte, size-40-8)
		msg := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: id, Seq: 1, Data: payload}}
		wire, err := msg.Marshal(nil)
		if err != nil {
			return err
		}
		if _, err := c.WriteTo(wire, &net.IPAddr{IP: dst.AsSlice()}); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65536)
		for {
			nr, _, err := c.ReadFrom(buf)
			if err != nil {
				return errNoReply
			}
			m, err := icmp.ParseMessage(58, buf[:nr])
			if err != nil {
				continue
			}
			switch m.Type {
			case ipv6.ICMPTypeEchoReply:
				if e, ok := m.Body.(*icmp.Echo); ok && e.ID == id {
					return nil
				}
			case ipv6.ICMPTypeDestinationUnreachable:
				return errUnreachable
			case ipv6.ICMPTypePacketTooBig:
				if b, ok := m.Body.(*icmp.PacketTooBig); ok {
					return &packetTooBigError{MTU: b.MTU}
				}
			}
		}
	})
}

// tunResponder answers ICMPv6 echo requests arriving on a TUN device, standing
// in for a site behind a connect session.
type tunResponder struct {
	f       *os.File
	echoes  atomic.Uint64
	largest atomic.Uint64
}

func newTUNResponder(t *testing.T, pod testNS) *tunResponder {
	t.Helper()
	r := &tunResponder{}
	pod.do(t, func() error {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		ifr, err := unix.NewIfreq(tunName)
		if err != nil {
			_ = unix.Close(fd)
			return err
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("attach to TUN %q: %w", tunName, err)
		}
		r.f = os.NewFile(uintptr(fd), tunName)
		return nil
	})
	t.Cleanup(func() { _ = r.f.Close() })
	go r.run()
	return r
}

func (r *tunResponder) run() {
	buf := make([]byte, 65536)
	for {
		n, err := r.f.Read(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if len(pkt) < 48 || pkt[0]>>4 != 6 || pkt[6] != 58 || pkt[40] != 128 {
			continue
		}
		if uint64(n) > r.largest.Load() {
			r.largest.Store(uint64(n))
		}
		reply := make([]byte, n)
		copy(reply, pkt)
		copy(reply[8:24], pkt[24:40])
		copy(reply[24:40], pkt[8:24])
		reply[7] = 64
		reply[40] = 129
		binary.BigEndian.PutUint16(reply[42:44], 0)
		binary.BigEndian.PutUint16(reply[42:44], icmp6Checksum(reply))
		// Counted before the reply is written: a test reads the count
		// once its ping returns, which can be before this goroutine runs
		// again after the write.
		r.echoes.Add(1)
		if _, err := r.f.Write(reply); err != nil {
			r.echoes.Add(^uint64(0))
		}
	}
}

// icmp6Checksum computes the ICMPv6 checksum of an IPv6 packet whose ICMPv6
// message starts right after the fixed header.
func icmp6Checksum(pkt []byte) uint16 {
	body := pkt[40:]
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(pkt[8:40])
	var tail [8]byte
	binary.BigEndian.PutUint32(tail[0:4], uint32(len(body)))
	tail[7] = 58
	add(tail[:])
	add(body)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// neighborsOn lists the IPv6 neighbor entries on a link, excluding
// link-local ones.
func neighborsOn(t *testing.T, n testNS, link string) map[netip.Addr]int {
	t.Helper()
	out := map[netip.Addr]int{}
	n.do(t, func() error {
		l, err := netlink.LinkByName(link)
		if err != nil {
			return err
		}
		neighs, err := netlink.NeighList(l.Attrs().Index, unix.AF_INET6)
		if err != nil {
			return err
		}
		for _, nb := range neighs {
			if a, ok := netip.AddrFromSlice(nb.IP); ok && !a.IsLinkLocalUnicast() && !a.IsMulticast() {
				out[a] = nb.State
			}
		}
		return nil
	})
	return out
}

// TestLeakWatchSeesTransmittedPackets is the control for every leak check:
// a packet routed out the uplink toward the watched destination must be
// counted, and one toward another destination must not.
func TestLeakWatchSeesTransmittedPackets(t *testing.T) {
	requireRoot(t)
	host := newHost(t)
	dst, other := netip.MustParseAddr("2001:db8:7::1"), netip.MustParseAddr("2001:db8:7::2")
	w := watchLeaks(t, host, uplinkName, dst)
	host.do(t, func() error {
		for _, to := range []netip.Addr{dst, other} {
			c, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(to, 9)))
			if err != nil {
				return err
			}
			_, _ = c.Write([]byte("leak"))
			_ = c.Close()
		}
		return nil
	})
	time.Sleep(200 * time.Millisecond)
	if got := w.stop(); got != 1 {
		t.Fatalf("watcher counted %d packets toward %s, want 1", got, dst)
	}
}
