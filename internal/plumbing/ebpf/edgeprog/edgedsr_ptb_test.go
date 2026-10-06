// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"encoding/binary"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	xdpRedirect = 4

	ipprotoICMPv6      = 58
	icmpv6PacketTooBig = 2
	icmpLen            = 8

	// fabricMTU is the link every test here routes both the backend's uSID and
	// the client over.
	fabricMTU = 1500
	// bigPayload makes a TCP packet of exactly fabricMTU bytes: it fits the
	// client's path, and not the fabric once the gateway adds its 40 bytes.
	bigPayload = fabricMTU - ip6Len - tcpLen
)

// fabricLinkMAC is the next hop every route in narrowFabric resolves to.
var fabricLinkMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}

// icmpBucket mirrors the C struct icmp_bucket, which bpf2go is not asked to
// generate a type for.
type icmpBucket struct {
	LastNs   uint64
	CreditNs uint64
}

// narrowFabric moves the calling test's thread into a fresh network namespace
// whose routes reach each of dsts over a link of mtu bytes. Every FIB
// lookup a test run makes resolves there: an encapsulated packet bigger than
// the link is refused for size with the route's MTU, and the Packet Too Big the
// gateway answers with is routed to the client.
//
// The thread stays locked for the test, since a namespace belongs to a thread,
// and is moved back afterwards. A thread that cannot be is left locked, which
// makes the runtime discard it rather than reuse it.
func narrowFabric(t *testing.T, mtu int, dsts ...netip.Addr) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open thread network namespace: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore original network namespace: %v", err)
			return
		}
		_ = unix.Close(orig)
		runtime.UnlockOSThread()
	})
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare network namespace: %v", err)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("look up lo: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("set lo up: %v", err)
	}
	// A test run's ingress device is this namespace's loopback, and
	// bpf_fib_lookup refuses to route for one that does not forward.
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644); err != nil {
		t.Fatalf("enable IPv6 forwarding: %v", err)
	}

	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fab0", MTU: mtu}}); err != nil {
		t.Fatalf("add fabric link: %v", err)
	}
	link, err := netlink.LinkByName("fab0")
	if err != nil {
		t.Fatalf("look up fabric link: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("set fabric link up: %v", err)
	}

	for _, dst := range dsts {
		ip := net.IP(dst.AsSlice())
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)},
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteAdd(route); err != nil {
			t.Fatalf("route %v over the fabric link: %v", dst, err)
		}
		neigh := &netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       netlink.FAMILY_V6,
			State:        netlink.NUD_PERMANENT,
			IP:           ip,
			HardwareAddr: fabricLinkMAC,
		}
		if err := netlink.NeighAdd(neigh); err != nil {
			t.Fatalf("neighbor %v on the fabric link: %v", dst, err)
		}
	}
}

// ptbFixture is one VIP with one backend, the backend's uSID and the client
// both reachable over narrowFabric's link.
type ptbFixture struct {
	objs   *EdgedsrObjects
	key    EdgedsrVipKey
	vip    netip.Addr
	client netip.Addr
}

func newPTBFixture(t *testing.T) *ptbFixture {
	t.Helper()
	return newPTBFixtureMTU(t, fabricMTU)
}

func newPTBFixtureMTU(t *testing.T, mtu int) *ptbFixture {
	t.Helper()
	requireRoot(t)

	f := &ptbFixture{
		vip:    netip.MustParseAddr("2001:db8::100"),
		client: netip.MustParseAddr("2001:db8:ffff::1"),
	}
	usid := netip.MustParseAddr("fc00:1:2::a1b2")
	narrowFabric(t, mtu, usid, f.client)

	f.objs = loadObjects(t)
	f.key = vipKey(ipprotoTCP, 8080, f.vip)
	var value EdgedsrVipValue
	value.BackendCount = 1
	value.Backends[0] = EdgedsrBackend{
		Addr: netip.MustParseAddr("fd20:60::5").As16(),
		Port: bswap16(30080),
		Usid: usid.As16(),
	}
	if err := f.objs.VipTable.Put(f.key, value); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}
	if err := f.objs.EncapConfigTable.Put(uint32(0), EdgedsrEncapConfig{
		EncapSrc: netip.MustParseAddr("fc00:0:2::1").As16(),
	}); err != nil {
		t.Fatalf("populate encap_config_table: %v", err)
	}
	return f
}

func (f *ptbFixture) run(t *testing.T, payload []byte) (uint32, []byte) {
	t.Helper()
	pkt := buildL4Packet(t, ipprotoTCP, f.vip, f.client, 41000, 8080, payload)
	ret, out, err := f.objs.EdgeLb.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	return ret, out
}

func (f *ptbFixture) vipStats(t *testing.T) EdgedsrVipStatsValue {
	t.Helper()
	var stats EdgedsrVipStatsValue
	if err := f.objs.VipStatsTable.Lookup(f.key, &stats); err != nil {
		t.Fatalf("lookup vip_stats_table: %v", err)
	}
	return stats
}

// TestEdgeLB_PacketTooBigForTheFabric covers a client packet that fits the
// client's path but not the fabric once the gateway adds its 40-byte outer
// header. The client used to hear nothing, so its path MTU discovery never
// adapted and every large packet to the VIP vanished. It now receives a Packet
// Too Big from the VIP, with an MTU that fits once encapsulated, quoting the
// packet it sent. The packet itself is still counted as a fib_frag_needed drop.
//
// A small packet on the same flow still reaches the backend: the check is the
// route's own, not a size the gateway picks.
func TestEdgeLB_PacketTooBigForTheFabric(t *testing.T) {
	f := newPTBFixture(t)

	if ret, _ := f.run(t, []byte("small")); ret != xdpRedirect {
		t.Fatalf("small packet verdict = %d, want XDP_REDIRECT (%d) over the fabric link", ret, xdpRedirect)
	}

	big := buildL4Packet(t, ipprotoTCP, f.vip, f.client, 41000, 8080, make([]byte, bigPayload))
	ret, out := f.run(t, make([]byte, bigPayload))
	if ret != xdpRedirect {
		t.Fatalf("verdict = %d, want XDP_REDIRECT (%d): the Packet Too Big routed to the client", ret, xdpRedirect)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonFibFragNeeded); got != 1 {
		t.Errorf("drop_reasons[fib_frag_needed] = %d, want 1 -- the packet is still dropped", got)
	}
	if stats := f.vipStats(t); stats.Packets != 2 || stats.DroppedPackets != 1 {
		t.Errorf("vip_stats packets/dropped = %d/%d, want 2/1", stats.Packets, stats.DroppedPackets)
	}

	if got := net.HardwareAddr(out[0:6]); got.String() != fabricLinkMAC.String() {
		t.Errorf("destination MAC = %v, want the route's next hop %v", got, fabricLinkMAC)
	}
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
		t.Errorf("EtherType = %#04x, want 0x86DD", got)
	}
	ip6 := out[ethLen:]
	if ip6[0]>>4 != 6 {
		t.Errorf("IP version = %d, want 6", ip6[0]>>4)
	}
	if ip6[6] != ipprotoICMPv6 || ip6[7] != 64 {
		t.Errorf("next header/hop limit = %d/%d, want %d/64", ip6[6], ip6[7], ipprotoICMPv6)
	}
	if got := addrAt(ip6, 8); got != f.vip {
		t.Errorf("source = %v, want the VIP %v", got, f.vip)
	}
	if got := addrAt(ip6, 24); got != f.client {
		t.Errorf("destination = %v, want the client %v", got, f.client)
	}
	msg := ip6[ip6Len:]
	if want := icmpLen + ip6Len + 8; len(msg) != want || int(binary.BigEndian.Uint16(ip6[4:6])) != want {
		t.Fatalf("message length = %d, payload length = %d, want both %d", len(msg),
			binary.BigEndian.Uint16(ip6[4:6]), want)
	}
	if msg[0] != icmpv6PacketTooBig || msg[1] != 0 {
		t.Errorf("type/code = %d/%d, want %d/0", msg[0], msg[1], icmpv6PacketTooBig)
	}
	if got := binary.BigEndian.Uint32(msg[4:8]); got != fabricMTU-ip6Len {
		t.Errorf("MTU = %d, want %d (the fabric's, less the gateway's encapsulation)", got, fabricMTU-ip6Len)
	}
	if string(msg[icmpLen:]) != string(big[ethLen:ethLen+ip6Len+8]) {
		t.Errorf("quote is not the packet the client sent:\n got % x\nwant % x",
			msg[icmpLen:], big[ethLen:ethLen+ip6Len+8])
	}
	assertICMP6Checksum(t, f.vip, f.client, msg)
}

// TestEdgeLB_PacketTooBigRateLimited covers the bucket refusing the error: the
// packet is dropped as before, and the refusal is counted.
func TestEdgeLB_PacketTooBigRateLimited(t *testing.T) {
	f := newPTBFixture(t)

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible CPUs: %v", err)
	}
	empty := make([]icmpBucket, cpus)
	for i := range empty {
		empty[i] = icmpBucket{LastNs: math.MaxUint64}
	}
	if err := f.objs.IcmpRateBucket.Put(uint32(0), empty); err != nil {
		t.Fatalf("empty icmp_rate_bucket: %v", err)
	}

	if ret, _ := f.run(t, make([]byte, bigPayload)); ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonFibFragNeeded); got != 1 {
		t.Errorf("drop_reasons[fib_frag_needed] = %d, want 1", got)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonICMPRateLimited); got != 1 {
		t.Errorf("drop_reasons[icmp_rate_limited] = %d, want 1", got)
	}
}

// TestEdgeLB_NoPacketTooBigBelowTheIPv6Minimum covers a fabric route too small
// to carry even a 1280-byte packet once encapsulated. A Packet Too Big would
// report less than 1280, which an IPv6 sender never goes below, so its next
// packet would fail the same way. The packet is dropped and counted, and no
// message is sent or charged to the rate limit.
func TestEdgeLB_NoPacketTooBigBelowTheIPv6Minimum(t *testing.T) {
	const mtu = 1300
	f := newPTBFixtureMTU(t, mtu)

	if ret, _ := f.run(t, make([]byte, mtu-ip6Len-tcpLen)); ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonFibFragNeeded); got != 1 {
		t.Errorf("drop_reasons[fib_frag_needed] = %d, want 1", got)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonICMPRateLimited); got != 0 {
		t.Errorf("drop_reasons[icmp_rate_limited] = %d, want 0 (no message attempted)", got)
	}
}

func addrAt(b []byte, off int) netip.Addr {
	return netip.AddrFrom16([16]byte(b[off : off+16]))
}

// assertICMP6Checksum recomputes msg's checksum over the IPv6 pseudo-header
// independently of the datapath and compares.
func assertICMP6Checksum(t *testing.T, src, dst netip.Addr, msg []byte) {
	t.Helper()
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	s, d := src.As16(), dst.As16()
	add(s[:])
	add(d[:])
	var lenProto [8]byte
	binary.BigEndian.PutUint32(lenProto[0:4], uint32(len(msg)))
	lenProto[7] = ipprotoICMPv6
	add(lenProto[:])
	zeroed := append([]byte{}, msg...)
	zeroed[2], zeroed[3] = 0, 0
	add(zeroed)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	want := ^uint16(sum)
	if got := binary.BigEndian.Uint16(msg[2:4]); got != want {
		t.Errorf("ICMPv6 checksum = %#04x, want %#04x (independent full recompute over %v -> %v)",
			got, want, src, dst)
	}
}
