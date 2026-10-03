// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

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
	// fabricMTU is the narrowed fabric link every test here routes the
	// tenant's worker uSID over.
	fabricMTU = 1300
	// bigPayload makes a reply that fits the internet path and not the fabric
	// once the shard re-encapsulates it.
	bigPayload = 1300
)

// fabricLinkMAC is the next hop every route in narrowFabric resolves to.
var fabricLinkMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}

// narrowFabric moves the calling test's thread into a fresh network namespace
// whose routes reach usid -- the tenant's worker node -- over a link of
// fabricMTU bytes, and reach each of peers over the same link. Every FIB lookup
// a test run makes resolves there: a reply too big for the fabric is refused
// for size, with the route's MTU, and the error the shard answers it with is
// routed to its peer.
//
// The thread stays locked for the test, since a namespace belongs to a thread,
// and is moved back afterwards. A thread that cannot be is left locked, which
// makes the runtime discard it rather than reuse it.
func narrowFabric(t *testing.T, usid netip.Addr, peers ...netip.Addr) {
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
	for _, path := range []string{
		"/proc/sys/net/ipv6/conf/all/forwarding",
		"/proc/sys/net/ipv4/conf/all/forwarding",
		"/proc/sys/net/ipv4/conf/lo/forwarding",
	} {
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
			t.Fatalf("enable forwarding via %s: %v", path, err)
		}
	}

	fabric := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fab0", MTU: fabricMTU}}
	if err := netlink.LinkAdd(fabric); err != nil {
		t.Fatalf("add fabric link: %v", err)
	}
	link, err := netlink.LinkByName("fab0")
	if err != nil {
		t.Fatalf("look up fabric link: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("set fabric link up: %v", err)
	}

	for _, dst := range append([]netip.Addr{usid}, peers...) {
		bits, family := 128, netlink.FAMILY_V6
		if dst.Is4() {
			bits, family = 32, netlink.FAMILY_V4
		}
		ip := net.IP(dst.AsSlice())
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)},
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteAdd(route); err != nil {
			t.Fatalf("route %v over the fabric link: %v", dst, err)
		}
		neigh := &netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       family,
			State:        netlink.NUD_PERMANENT,
			IP:           ip,
			HardwareAddr: fabricLinkMAC,
		}
		if err := netlink.NeighAdd(neigh); err != nil {
			t.Fatalf("neighbor %v on the fabric link: %v", dst, err)
		}
	}
}

// emptyBucket drains every CPU's icmp_rate_bucket; see
// TestEchoResponder_RateLimited.
func emptyBucket(t *testing.T, objs *NatObjects) {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible CPUs: %v", err)
	}
	empty := make([]icmpBucket, cpus)
	for i := range empty {
		empty[i] = icmpBucket{LastNs: math.MaxUint64}
	}
	if err := objs.IcmpRateBucket.Put(uint32(0), empty); err != nil {
		t.Fatalf("empty icmp_rate_bucket: %v", err)
	}
}

// TestPacketTooBig_ReplyTooBigForTheFabric covers a NAT66 reply that fits the
// internet path but not the fabric once re-encapsulated. Its sender used to
// hear nothing; it now receives a Packet Too Big from the masquerade address
// it was talking to, with an MTU that fits once the shard adds its 40 bytes,
// quoting the packet as it was sent -- before translation, which is what the
// sender's stack matches on.
//
// A small reply on the same flow still reaches the tenant: the check is the
// route's own, not a size the shard picks.
func TestPacketTooBig_ReplyTooBigForTheFabric(t *testing.T) {
	f := newNAT66Fixture(t)
	narrowFabric(t, f.backendUSID, f.peer)

	out := f.sendUDP(t)
	masqPort := binary.BigEndian.Uint16(out[ethLen+ip6Len:])

	small := buildUDPPacket(t, f.shardPub, f.peer, encappedDstPort, masqPort, []byte("small"))
	if ret, _ := f.run(t, small); ret != xdpRedirect {
		t.Fatalf("small reply verdict = %d, want XDP_REDIRECT (%d) over the fabric link", ret, xdpRedirect)
	}

	big := buildUDPPacket(t, f.shardPub, f.peer, encappedDstPort, masqPort, make([]byte, bigPayload))
	ret, out := f.run(t, big)
	if ret != xdpRedirect {
		t.Fatalf("verdict = %d, want XDP_REDIRECT (%d): the Packet Too Big routed to its sender", ret, xdpRedirect)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibFragNeeded); got != 1 {
		t.Errorf("drop_reasons[fib_frag_needed] = %d, want 1 -- the reply is still dropped", got)
	}

	if got := net.HardwareAddr(out[0:6]); got.String() != fabricLinkMAC.String() {
		t.Errorf("destination MAC = %v, want the route's next hop %v", got, fabricLinkMAC)
	}
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
		t.Errorf("EtherType = %#04x, want 0x86DD", got)
	}
	ip6 := out[ethLen:]
	if ip6[6] != ipprotoICMPv6 || ip6[7] != 64 {
		t.Errorf("next header/hop limit = %d/%d, want %d/64", ip6[6], ip6[7], ipprotoICMPv6)
	}
	if got := addrAt(ip6, 8); got != f.shardPub {
		t.Errorf("source = %v, want the masquerade address %v", got, f.shardPub)
	}
	if got := addrAt(ip6, 24); got != f.peer {
		t.Errorf("destination = %v, want the sender %v", got, f.peer)
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
		t.Errorf("MTU = %d, want %d (the fabric's, less the shard's encapsulation)", got, fabricMTU-ip6Len)
	}
	if string(msg[icmpLen:]) != string(big[ethLen:ethLen+ip6Len+8]) {
		t.Errorf("quote is not the reply as its sender sent it:\n got % x\nwant % x",
			msg[icmpLen:], big[ethLen:ethLen+ip6Len+8])
	}
	assertICMP6Checksum(t, f.shardPub, f.peer, msg)
}

// TestFragmentationNeeded_ReplyTooBigForTheFabric is the NAT64 case: an IPv4
// sender hears an ICMPv4 Fragmentation Needed, and the MTU it is told leaves
// room for the 20 bytes translation adds as well as the encapsulation's 40.
func TestFragmentationNeeded_ReplyTooBigForTheFabric(t *testing.T) {
	f := newNAT64Fixture(t, 0)
	narrowFabric(t, f.backendUSID, f.peer4)

	out := f.sendUDP64(t, []byte("out"))
	masqPort := binary.BigEndian.Uint16(out[ip4Len:])

	big := buildIPv4UDPPacket(t, f.shardPub4, f.peer4, encappedDstPort, masqPort, make([]byte, bigPayload))
	ret, got := f.run(t, big)
	if ret != xdpRedirect {
		t.Fatalf("verdict = %d, want XDP_REDIRECT (%d): the Fragmentation Needed routed to its sender", ret, xdpRedirect)
	}
	if n := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibFragNeeded); n != 1 {
		t.Errorf("drop_reasons[fib_frag_needed] = %d, want 1", n)
	}

	if et := binary.BigEndian.Uint16(got[12:14]); et != 0x0800 {
		t.Fatalf("EtherType = %#04x, want 0x0800", et)
	}
	ip := got[ethLen:]
	if ip[0] != 0x45 || ip[9] != ipprotoICMP || ip[8] != 64 {
		t.Errorf("version/IHL, protocol, TTL = %#02x, %d, %d; want 0x45, %d, 64", ip[0], ip[9], ip[8], ipprotoICMP)
	}
	if src := netip.AddrFrom4([4]byte(ip[12:16])); src != f.shardPub4 {
		t.Errorf("source = %v, want %v", src, f.shardPub4)
	}
	if dst := netip.AddrFrom4([4]byte(ip[16:20])); dst != f.peer4 {
		t.Errorf("destination = %v, want %v", dst, f.peer4)
	}
	assertIPv4HeaderChecksum(t, ip)

	msg := ip[ip4Len:]
	if want := icmpLen + ip4Len + 8; len(msg) != want || int(binary.BigEndian.Uint16(ip[2:4])) != ip4Len+want {
		t.Fatalf("message length = %d, total length = %d, want %d and %d", len(msg),
			binary.BigEndian.Uint16(ip[2:4]), want, ip4Len+want)
	}
	if msg[0] != icmpDestUnreach || msg[1] != 4 {
		t.Errorf("type/code = %d/%d, want %d/4", msg[0], msg[1], icmpDestUnreach)
	}
	wantMTU := uint16(fabricMTU - ip6Len - (ip6Len - ip4Len))
	if mtu := binary.BigEndian.Uint16(msg[6:8]); mtu != wantMTU {
		t.Errorf("next-hop MTU = %d, want %d (the fabric's, less encapsulation and translation)", mtu, wantMTU)
	}
	if string(msg[icmpLen:]) != string(big[ethLen:ethLen+ip4Len+8]) {
		t.Errorf("quote is not the reply as its sender sent it:\n got % x\nwant % x",
			msg[icmpLen:], big[ethLen:ethLen+ip4Len+8])
	}
	assertICMP4Checksum(t, msg)
}

// TestPacketTooBig_NoneAboutAnError covers the rule every router follows: an
// ICMP error is never answered with another. A translated error too big for
// the fabric is dropped and counted, and its sender hears nothing.
func TestPacketTooBig_NoneAboutAnError(t *testing.T) {
	f := newNAT66Fixture(t)
	narrowFabric(t, f.backendUSID, f.peer)

	ret, out := f.run(t, buildEncappedUDPPacket(t, sidWithArgument(f.shardSID, 0x123), f.backendUSID,
		f.backend, f.peer, make([]byte, bigPayload)))
	assertLeftFromDatapath(t, ret)
	quoted := out[ethLen:]
	// The big forward packet above is itself too big for the narrowed link to
	// the peer, so the counter is read as a delta across the error alone.
	before := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibFragNeeded)

	router := netip.MustParseAddr("2001:db8:7777::1")
	ret, out = f.run(t, buildICMPv6Packet(router, f.shardPub, icmpMessage(icmpv6TimeExceeded, 0, 0, quoted)))
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibFragNeeded) - before; got != 1 {
		t.Errorf("drop_reasons[fib_frag_needed] rose by %d, want 1", got)
	}
	if out[ethLen+6] != 41 {
		t.Errorf("outer next header = %d, want 41: the encapsulated error, not a new one built over it",
			out[ethLen+6])
	}
}

// TestPacketTooBig_RateLimited covers the bucket refusing the error: the reply
// is dropped as before, and the refusal is counted.
func TestPacketTooBig_RateLimited(t *testing.T) {
	f := newNAT66Fixture(t)
	narrowFabric(t, f.backendUSID, f.peer)

	out := f.sendUDP(t)
	masqPort := binary.BigEndian.Uint16(out[ethLen+ip6Len:])
	emptyBucket(t, f.objs)

	ret, _ := f.run(t, buildUDPPacket(t, f.shardPub, f.peer, encappedDstPort, masqPort, make([]byte, bigPayload)))
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatICMPRateLimited); got != 1 {
		t.Errorf("drop_reasons[icmp_rate_limited] = %d, want 1", got)
	}
}
