// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

const (
	ip4Len          = 20
	ipprotoICMP     = 1
	ipprotoIPIP     = 4
	icmpDestUnreach = 3
	icmpFragNeeded  = 4
	ipDF            = 0x4000
	ipMF            = 0x2000
)

var (
	testVIP4    = netip.MustParseAddr("192.0.2.10")
	testClient4 = netip.MustParseAddr("198.51.100.7")
	testUSID    = netip.MustParseAddr("fc00:1:2::a1b2")
	testEncap   = netip.MustParseAddr("fc00:0:2::1")
)

// ip4Opts shapes the packet buildIPv4Packet writes.
type ip4Opts struct {
	options  []byte // IPv4 options, a multiple of 4 bytes
	fragOff  uint16 // the frag_off field, flags included
	ttl      byte
	padding  int // bytes after the IPv4 packet, as Ethernet padding
	totalAdj int // added to the true total length, to build a malformed header
}

// buildIPv4Packet builds an Ethernet+IPv4+TCP or +UDP frame with a valid IPv4
// header checksum.
func buildIPv4Packet(t *testing.T, proto uint8, dst, src netip.Addr, srcPort, dstPort uint16,
	payload []byte, o ip4Opts,
) []byte {
	t.Helper()
	if o.ttl == 0 {
		o.ttl = 64
	}
	hlen := ip4Len + len(o.options)
	l4 := l4HeaderLen(proto)
	total := hlen + l4 + len(payload)

	pkt := []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x08, 0x00}
	hdr := make([]byte, ip4Len, ip4Len+len(o.options))
	hdr[0] = 0x40 | byte(hlen/4)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total+o.totalAdj))
	binary.BigEndian.PutUint16(hdr[4:6], 0x1234)
	binary.BigEndian.PutUint16(hdr[6:8], o.fragOff)
	hdr[8] = o.ttl
	hdr[9] = proto
	s, d := src.As4(), dst.As4()
	copy(hdr[12:16], s[:])
	copy(hdr[16:20], d[:])
	hdr = append(hdr, o.options...)
	binary.BigEndian.PutUint16(hdr[10:12], ipv4Checksum(hdr))
	pkt = append(pkt, hdr...)

	pkt = append(pkt, byte(srcPort>>8), byte(srcPort), byte(dstPort>>8), byte(dstPort))
	if proto == ipprotoTCP {
		pkt = append(pkt, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0)
	} else {
		ul := uint16(l4 + len(payload))
		pkt = append(pkt, byte(ul>>8), byte(ul), 0, 0)
	}
	pkt = append(pkt, payload...)
	return append(pkt, make([]byte, o.padding)...)
}

// ipv4Checksum is the Internet checksum of b, computed with its own checksum
// field, if any, already zeroed by the caller or included as-is to verify.
func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// putIPv4VIP loads proto/port on vip with the given backend uSIDs, slots
// alternating between them, and this node's encapsulation source.
func putIPv4VIP(t *testing.T, objs *EdgedsrObjects, proto uint8, port uint16, vip netip.Addr,
	usids ...netip.Addr,
) EdgedsrVipKey {
	t.Helper()
	var value EdgedsrVipValue
	value.BackendCount = uint32(len(usids))
	for i, u := range usids {
		value.Backends[i] = EdgedsrBackend{
			Addr: netip.AddrFrom4([4]byte{10, 60, 0, byte(5 + i)}).As16(),
			Port: bswap16(30080),
			Usid: u.As16(),
		}
	}
	for i := range value.MaglevTable {
		if len(usids) > 0 {
			value.MaglevTable[i] = uint8(i % len(usids))
		}
	}
	key := vipKey(proto, port, vip)
	if err := objs.VipTable.Put(key, value); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}
	if err := objs.VipAddrTable.Put(vipAddrKey(vip), EdgedsrVipAddrValue{Generation: 1}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}
	if err := objs.EncapConfigTable.Put(uint32(0), EdgedsrEncapConfig{EncapSrc: testEncap.As16()}); err != nil {
		t.Fatalf("populate encap_config_table: %v", err)
	}
	return key
}

// narrowFabric4 is narrowFabric, at fabricMTU, with IPv4 routes and neighbors
// too, and IPv4 forwarding on, since bpf_fib_lookup refuses an IPv4 lookup on
// an ingress device that does not forward.
func narrowFabric4(t *testing.T, v6 []netip.Addr, v4 ...netip.Addr) {
	t.Helper()
	narrowFabric(t, fabricMTU, v6...)
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/forwarding", []byte("1"), 0o644); err != nil {
		t.Fatalf("enable IPv4 forwarding: %v", err)
	}
	link, err := netlink.LinkByName("fab0")
	if err != nil {
		t.Fatalf("look up fabric link: %v", err)
	}
	for _, dst := range v4 {
		ip := net.IP(dst.AsSlice())
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
			Scope:     netlink.SCOPE_LINK,
		}); err != nil {
			t.Fatalf("route %v over the fabric link: %v", dst, err)
		}
		if err := netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       netlink.FAMILY_V4,
			State:        netlink.NUD_PERMANENT,
			IP:           ip,
			HardwareAddr: fabricLinkMAC,
		}); err != nil {
			t.Fatalf("neighbor %v on the fabric link: %v", dst, err)
		}
	}
}

func runLB(t *testing.T, objs *EdgedsrObjects, pkt []byte) (uint32, []byte) {
	t.Helper()
	ret, out, err := objs.EdgeLb.Test(pkt)
	if err != nil {
		t.Fatalf("edge_lb test-run: %v", err)
	}
	return ret, out
}

// assertIPv4Encapsulated checks out is pkt's IPv4 packet, without any
// padding, inside an outer IPv6 header with Next Header 4 to usid.
func assertIPv4Encapsulated(t *testing.T, pkt, out []byte, usid netip.Addr) {
	t.Helper()
	inner := pkt[ethLen : ethLen+int(binary.BigEndian.Uint16(pkt[ethLen+2:ethLen+4]))]
	if len(out) != ethLen+ip6Len+len(inner) {
		t.Fatalf("output is %d bytes, want %d: Ethernet, outer IPv6 and the inner packet without padding",
			len(out), ethLen+ip6Len+len(inner))
	}
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
		t.Errorf("EtherType = %#04x, want 0x86DD", got)
	}
	outer := out[ethLen:]
	if outer[0]>>4 != 6 || outer[6] != ipprotoIPIP {
		t.Errorf("outer version/next header = %d/%d, want 6/%d", outer[0]>>4, outer[6], ipprotoIPIP)
	}
	if got := int(binary.BigEndian.Uint16(outer[4:6])); got != len(inner) {
		t.Errorf("outer payload length = %d, want the inner packet's %d", got, len(inner))
	}
	if got := addrAt(outer, 24); got != usid {
		t.Errorf("outer destination = %v, want the backend uSID %v", got, usid)
	}
	if got := addrAt(outer, 8); got != testEncap {
		t.Errorf("outer source = %v, want the encap source %v", got, testEncap)
	}
	if string(out[ethLen+ip6Len:]) != string(inner) {
		t.Errorf("inner packet was modified:\n got % x\nwant % x", out[ethLen+ip6Len:], inner)
	}
}

// TestEdgeLB_IPv4ClaimedAndEncapsulated covers requirement 1 and 2 of #705:
// an IPv4 TCP or UDP packet to an IPv4 VIP is claimed, sent to its backend's
// uSID, and carried byte-for-byte inside an outer IPv6 header with Next Header
// 4, the client's IPv4 source untouched.
func TestEdgeLB_IPv4ClaimedAndEncapsulated(t *testing.T) {
	for _, proto := range []uint8{ipprotoTCP, ipprotoUDP} {
		t.Run(map[uint8]string{ipprotoTCP: "tcp", ipprotoUDP: "udp"}[proto], func(t *testing.T) {
			requireRoot(t)
			narrowFabric4(t, []netip.Addr{testUSID})
			objs := loadObjects(t)
			key := putIPv4VIP(t, objs, proto, 443, testVIP4, testUSID)

			pkt := buildIPv4Packet(t, proto, testVIP4, testClient4, 41000, 443, []byte("hello"), ip4Opts{fragOff: ipDF})
			ret, out := runLB(t, objs, pkt)
			if ret != xdpRedirect {
				t.Fatalf("verdict = %d, want XDP_REDIRECT (%d) over the fabric link", ret, xdpRedirect)
			}
			assertIPv4Encapsulated(t, pkt, out, testUSID)

			var stats EdgedsrVipStatsValue
			if err := objs.VipStatsTable.Lookup(key, &stats); err != nil {
				t.Fatalf("lookup vip_stats_table: %v", err)
			}
			if stats.Packets != 1 || stats.DroppedPackets != 0 {
				t.Errorf("vip_stats packets/dropped = %d/%d, want 1/0", stats.Packets, stats.DroppedPackets)
			}
		})
	}
}

// TestEdgeLB_IPv4OptionsAndPadding covers a header with options, carried
// unchanged with the ports read past them, and a short frame's Ethernet
// padding, trimmed so the outer payload length is exactly the IPv4 packet's.
func TestEdgeLB_IPv4OptionsAndPadding(t *testing.T) {
	requireRoot(t)
	narrowFabric4(t, []netip.Addr{testUSID})
	objs := loadObjects(t)
	putIPv4VIP(t, objs, ipprotoUDP, 53, testVIP4, testUSID)

	tests := []struct {
		name string
		opts ip4Opts
	}{
		{"options", ip4Opts{options: []byte{0x94, 0x04, 0x00, 0x00}}}, // Router Alert
		{"padding", ip4Opts{padding: 18}},
		{"options and padding", ip4Opts{options: []byte{0x01, 0x01, 0x01, 0x00}, padding: 6}},
	}
	// A plain loop, not subtests: a subtest's goroutine may run on another
	// thread, outside the namespace narrowFabric4 put this one in.
	for _, tt := range tests {
		pkt := buildIPv4Packet(t, ipprotoUDP, testVIP4, testClient4, 41000, 53, []byte("q"), tt.opts)
		ret, out := runLB(t, objs, pkt)
		if ret != xdpRedirect {
			t.Errorf("%s: verdict = %d, want XDP_REDIRECT (%d)", tt.name, ret, xdpRedirect)
			continue
		}
		assertIPv4Encapsulated(t, pkt, out, testUSID)
	}
}

// TestEdgeLB_IPv4MaglevAnswersAlikeEverywhere covers anycast: two independent
// loads of the program, as two gateway nodes would hold, send every flow to
// the same backend, and several source ports spread over both backends. With
// no route to either uSID the FIB lookup fails, but the outer header is
// already written, which is what is read here.
func TestEdgeLB_IPv4MaglevAnswersAlikeEverywhere(t *testing.T) {
	requireRoot(t)
	usidA, usidB := netip.MustParseAddr("fc00:1:a::1"), netip.MustParseAddr("fc00:1:b::1")
	nodes := []*EdgedsrObjects{loadObjects(t), loadObjects(t)}
	for _, objs := range nodes {
		putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, usidA, usidB)
	}

	seen := map[netip.Addr]bool{}
	for sport := uint16(40000); sport < 40032; sport++ {
		chosen := make([]netip.Addr, 0, len(nodes))
		for _, objs := range nodes {
			pkt := buildIPv4Packet(t, ipprotoTCP, testVIP4, testClient4, sport, 443, nil, ip4Opts{})
			_, out := runLB(t, objs, pkt)
			chosen = append(chosen, addrAt(out[ethLen:], 24))
		}
		if chosen[0] != chosen[1] {
			t.Errorf("source port %d: node one chose %v, node two %v", sport, chosen[0], chosen[1])
		}
		seen[chosen[0]] = true
	}
	if !seen[usidA] || !seen[usidB] {
		t.Errorf("32 source ports reached only %v, want both backends", seen)
	}
}

// TestEdgeLB_IPv4Fragments covers fragments: one addressed to a VIP is a
// counted drop, first fragment or later, since a later fragment has no ports
// to pick a backend by; one addressed elsewhere is not claimed.
func TestEdgeLB_IPv4Fragments(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	putIPv4VIP(t, objs, ipprotoUDP, 53, testVIP4, testUSID)

	tests := []struct {
		name string
		dst  netip.Addr
		frag uint16
		want uint32
	}{
		{"first fragment to a VIP", testVIP4, ipMF, xdpDrop},
		{"later fragment to a VIP", testVIP4, 185, xdpDrop},
		{"last fragment to a VIP", testVIP4, 370, xdpDrop},
		{"fragment elsewhere", netip.MustParseAddr("192.0.2.99"), ipMF, xdpPass},
	}
	var drops uint64
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := buildIPv4Packet(t, ipprotoUDP, tt.dst, testClient4, 41000, 53, []byte("frag"),
				ip4Opts{fragOff: tt.frag})
			if ret, _ := runLB(t, objs, pkt); ret != tt.want {
				t.Errorf("verdict = %d, want %d", ret, tt.want)
			}
			if tt.want == xdpDrop {
				drops++
			}
			if got := sumPerCPU(t, objs.DropReasons, DropReasonIPv4Fragment); got != drops {
				t.Errorf("drop_reasons[ipv4_fragment] = %d, want %d", got, drops)
			}
		})
	}
}

// TestEdgeLB_IPv4MalformedIsNotClaimed covers headers too short, too long or
// of the wrong version to judge: each is passed on for the kernel to judge,
// with no drop counted and no row created for the VIP.
func TestEdgeLB_IPv4MalformedIsNotClaimed(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	key := putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, testUSID)

	good := func() []byte {
		return buildIPv4Packet(t, ipprotoTCP, testVIP4, testClient4, 41000, 443, nil, ip4Opts{})
	}
	tests := []struct {
		name string
		pkt  func() []byte
	}{
		{"truncated header", func() []byte { return good()[:ethLen+12] }},
		{"version 5", func() []byte { p := good(); p[ethLen] = 0x55; return p }},
		{"header length under 20", func() []byte { p := good(); p[ethLen] = 0x44; return p }},
		{"total length under the header", func() []byte {
			return buildIPv4Packet(t, ipprotoTCP, testVIP4, testClient4, 41000, 443, nil, ip4Opts{totalAdj: -30})
		}},
		{"total length past the frame", func() []byte {
			return buildIPv4Packet(t, ipprotoTCP, testVIP4, testClient4, 41000, 443, nil, ip4Opts{totalAdj: 100})
		}},
		{"TCP header past the total length", func() []byte {
			return buildIPv4Packet(t, ipprotoTCP, testVIP4, testClient4, 41000, 443, nil, ip4Opts{totalAdj: -10})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if ret, _ := runLB(t, objs, tt.pkt()); ret != xdpPass {
				t.Errorf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
			}
		})
	}
	for i := range DropReasonCount {
		if got := sumPerCPU(t, objs.DropReasons, i); got != 0 {
			t.Errorf("drop_reasons[%s] = %d, want 0", DropReasonNames[i], got)
		}
	}
	var stats EdgedsrVipStatsValue
	if err := objs.VipStatsTable.Lookup(key, &stats); err == nil {
		t.Errorf("vip_stats row created for unclaimed packets: %+v", stats)
	}
}

// TestEdgeLB_IPv4FragmentationNeeded covers a Don't Fragment packet too big
// for the fabric once encapsulated: the client gets an ICMPv4 Destination
// Unreachable, Fragmentation Needed, from the VIP, with the fabric's MTU less
// the encapsulation and a quote of its header and first 8 bytes. The packet
// itself is still a fib_frag_needed drop.
func TestEdgeLB_IPv4FragmentationNeeded(t *testing.T) {
	requireRoot(t)
	narrowFabric4(t, []netip.Addr{testUSID}, testClient4)
	objs := loadObjects(t)
	putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, testUSID)

	big := buildIPv4Packet(t, ipprotoTCP, testVIP4, testClient4, 41000, 443,
		make([]byte, fabricMTU-ip4Len-tcpLen), ip4Opts{fragOff: ipDF})
	ret, out := runLB(t, objs, big)
	if ret != xdpRedirect {
		t.Fatalf("verdict = %d, want XDP_REDIRECT (%d): the error routed to the client", ret, xdpRedirect)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibFragNeeded); got != 1 {
		t.Errorf("drop_reasons[fib_frag_needed] = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x0800 {
		t.Errorf("EtherType = %#04x, want 0x0800", got)
	}
	if got := net.HardwareAddr(out[0:6]); got.String() != fabricLinkMAC.String() {
		t.Errorf("destination MAC = %v, want %v", got, fabricLinkMAC)
	}
	ip := out[ethLen:]
	const msgLen = icmpLen + ip4Len + 8
	if len(ip) != ip4Len+msgLen || int(binary.BigEndian.Uint16(ip[2:4])) != ip4Len+msgLen {
		t.Fatalf("packet = %d bytes, total length %d, want both %d", len(ip),
			binary.BigEndian.Uint16(ip[2:4]), ip4Len+msgLen)
	}
	if ip[0] != 0x45 || ip[8] != 64 || ip[9] != ipprotoICMP {
		t.Errorf("version-IHL/TTL/protocol = %#x/%d/%d, want 0x45/64/%d", ip[0], ip[8], ip[9], ipprotoICMP)
	}
	if ipv4Checksum(ip[:ip4Len]) != 0 {
		t.Errorf("IPv4 header checksum does not verify: % x", ip[:ip4Len])
	}
	if got := netip.AddrFrom4([4]byte(ip[12:16])); got != testVIP4 {
		t.Errorf("source = %v, want the VIP %v", got, testVIP4)
	}
	if got := netip.AddrFrom4([4]byte(ip[16:20])); got != testClient4 {
		t.Errorf("destination = %v, want the client %v", got, testClient4)
	}
	msg := ip[ip4Len:]
	if msg[0] != icmpDestUnreach || msg[1] != icmpFragNeeded {
		t.Errorf("type/code = %d/%d, want %d/%d", msg[0], msg[1], icmpDestUnreach, icmpFragNeeded)
	}
	if got := binary.BigEndian.Uint16(msg[6:8]); got != fabricMTU-ip6Len {
		t.Errorf("next-hop MTU = %d, want %d", got, fabricMTU-ip6Len)
	}
	if ipv4Checksum(msg) != 0 {
		t.Errorf("ICMP checksum does not verify")
	}
	if string(msg[icmpLen:]) != string(big[ethLen:ethLen+ip4Len+8]) {
		t.Errorf("quote is not the packet the client sent:\n got % x\nwant % x",
			msg[icmpLen:], big[ethLen:ethLen+ip4Len+8])
	}
}

// TestEdgeLB_IPv4TooBigWithoutAnAnswer covers the same packet without
// Don't Fragment, or with options: a router would fragment the first, which
// this program cannot, and the second cannot be quoted in the fixed message,
// so both are counted drops with no message attempted.
func TestEdgeLB_IPv4TooBigWithoutAnAnswer(t *testing.T) {
	requireRoot(t)
	narrowFabric4(t, []netip.Addr{testUSID}, testClient4)
	objs := loadObjects(t)
	putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, testUSID)

	for i, o := range []ip4Opts{{}, {fragOff: ipDF, options: []byte{1, 1, 1, 0}}} {
		pkt := buildIPv4Packet(t, ipprotoTCP, testVIP4, testClient4, 41000, 443,
			make([]byte, fabricMTU-ip4Len-tcpLen-len(o.options)), o)
		if ret, _ := runLB(t, objs, pkt); ret != xdpDrop {
			t.Errorf("case %d: verdict = %d, want XDP_DROP (%d)", i, ret, xdpDrop)
		}
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibFragNeeded); got != 2 {
		t.Errorf("drop_reasons[fib_frag_needed] = %d, want 2", got)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonICMPRateLimited); got != 0 {
		t.Errorf("drop_reasons[icmp_rate_limited] = %d, want 0 (no message attempted)", got)
	}
}

func runReturn(t *testing.T, objs *EdgedsrObjects, pkt []byte) (uint32, []byte) {
	t.Helper()
	ret, out, err := objs.EdgeReturn.Test(pkt)
	if err != nil {
		t.Fatalf("edge_return test-run: %v", err)
	}
	return ret, out
}

// TestEdgeReturn_IPv4ForwardsWithTTLAndChecksum covers requirement 3 of #705
// on the edge node: a reply sourced from an IPv4 VIP is forwarded with its TTL
// decremented and its header checksum still valid, and nothing past the
// header changed.
func TestEdgeReturn_IPv4ForwardsWithTTLAndChecksum(t *testing.T) {
	requireRoot(t)
	narrowFabric4(t, nil, testClient4)
	objs := loadObjects(t)
	if err := objs.VipAddrTable.Put(vipAddrKey(testVIP4), EdgedsrVipAddrValue{Generation: 1}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}

	// Each TTL runs plainly and again with the header's identification chosen
	// so the checksum sits where the incremental update must carry: the
	// decrement adds 0x0100 to it, so a checksum of 0xff00 or above wraps.
	type tc struct {
		ttl   byte
		check int // the checksum to force, or -1 to leave the packet as built
	}
	cases := []tc{
		{64, -1}, {2, -1}, {255, -1},
		{64, 0x0000}, {64, 0x00ff}, {64, 0xfeff}, {64, 0xff00}, {64, 0xfffe},
	}
	for _, c := range cases {
		ttl := c.ttl
		pkt := buildIPv4Packet(t, ipprotoTCP, testClient4, testVIP4, 443, 41000, []byte("reply"),
			ip4Opts{ttl: ttl, fragOff: ipDF})
		if c.check >= 0 {
			forceIPv4Checksum(t, pkt[ethLen:ethLen+ip4Len], uint16(c.check))
		}
		ret, out := runReturn(t, objs, pkt)
		if ret != xdpRedirect {
			t.Fatalf("TTL %d: verdict = %d, want XDP_REDIRECT (%d)", ttl, ret, xdpRedirect)
		}
		if got := binary.BigEndian.Uint16(out[12:14]); got != 0x0800 {
			t.Errorf("TTL %d: EtherType = %#04x, want 0x0800", ttl, got)
		}
		ip := out[ethLen:]
		if ip[8] != ttl-1 {
			t.Errorf("TTL = %d, want %d", ip[8], ttl-1)
		}
		if ipv4Checksum(ip[:ip4Len]) != 0 {
			t.Errorf("TTL %d: header checksum does not verify after the decrement: % x", ttl, ip[:ip4Len])
		}
		if string(ip[ip4Len:]) != string(pkt[ethLen+ip4Len:]) {
			t.Errorf("TTL %d: packet past the header changed", ttl)
		}
	}
	var stats EdgedsrVipStatsValue
	if err := objs.VipReturnStatsTable.Lookup(vipAddrKey(testVIP4), &stats); err != nil {
		t.Fatalf("lookup vip_return_stats_table: %v", err)
	}
	if want := uint64(len(cases)); stats.Packets != want || stats.DroppedPackets != 0 {
		t.Errorf("return stats packets/dropped = %d/%d, want %d/0", stats.Packets, stats.DroppedPackets, want)
	}
}

// forceIPv4Checksum rewrites hdr's identification so its valid header
// checksum is want.
func forceIPv4Checksum(t *testing.T, hdr []byte, want uint16) {
	t.Helper()
	for id := range 1 << 16 {
		binary.BigEndian.PutUint16(hdr[4:6], uint16(id))
		binary.BigEndian.PutUint16(hdr[10:12], 0)
		if sum := ipv4Checksum(hdr); sum == want {
			binary.BigEndian.PutUint16(hdr[10:12], sum)
			return
		}
	}
	t.Fatalf("no identification gives header checksum %#04x", want)
}

// TestEdgeReturn_IPv4MalformedIsNotClaimed is the return-side twin of
// TestEdgeLB_IPv4MalformedIsNotClaimed: a reply from a VIP address whose
// header does not validate is left to the kernel, uncounted.
func TestEdgeReturn_IPv4MalformedIsNotClaimed(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	if err := objs.VipAddrTable.Put(vipAddrKey(testVIP4), EdgedsrVipAddrValue{Generation: 1}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}

	good := func() []byte {
		return buildIPv4Packet(t, ipprotoUDP, testClient4, testVIP4, 53, 41000, nil, ip4Opts{})
	}
	tests := []struct {
		name string
		pkt  func() []byte
	}{
		{"truncated header", func() []byte { return good()[:ethLen+12] }},
		{"version 5", func() []byte { p := good(); p[ethLen] = 0x55; return p }},
		{"header length under 20", func() []byte { p := good(); p[ethLen] = 0x44; return p }},
		{"total length under the header", func() []byte {
			return buildIPv4Packet(t, ipprotoUDP, testClient4, testVIP4, 53, 41000, nil, ip4Opts{totalAdj: -20})
		}},
		{"total length past the frame", func() []byte {
			return buildIPv4Packet(t, ipprotoUDP, testClient4, testVIP4, 53, 41000, nil, ip4Opts{totalAdj: 100})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if ret, _ := runReturn(t, objs, tt.pkt()); ret != xdpPass {
				t.Errorf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
			}
		})
	}
	for i := range DropReasonCount {
		if got := sumPerCPU(t, objs.DropReasons, i); got != 0 {
			t.Errorf("drop_reasons[%s] = %d, want 0", DropReasonNames[i], got)
		}
	}
	var stats EdgedsrVipStatsValue
	if err := objs.VipReturnStatsTable.Lookup(vipAddrKey(testVIP4), &stats); err == nil {
		t.Errorf("vip_return_stats row created for unclaimed packets: %+v", stats)
	}
}

// TestEdgedsr_IPv6PathsIgnoreIPv4MappedAddresses covers the family boundary
// inside the datapath: an IPv4 VIP's rows are keyed as ::ffff:a.b.c.d, and a
// native IPv6 packet carrying that address is not one of this gateway's, so
// neither the forward nor the return IPv6 path claims it.
func TestEdgedsr_IPv6PathsIgnoreIPv4MappedAddresses(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	key := putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, testUSID)
	mapped := netip.AddrFrom16(testVIP4.As16())
	client6 := netip.MustParseAddr("2001:db8:c::7")

	if ret, _ := runLB(t, objs, buildL4Packet(t, ipprotoTCP, mapped, client6, 41000, 443, nil)); ret != xdpPass {
		t.Errorf("edge_lb verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
	if ret, _ := runReturn(t, objs, buildReturnPacket(t, mapped, client6, 64)); ret != xdpPass {
		t.Errorf("edge_return verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}

	var stats EdgedsrVipStatsValue
	if err := objs.VipStatsTable.Lookup(key, &stats); err == nil {
		t.Errorf("vip_stats row created by an IPv6 packet: %+v", stats)
	}
	if err := objs.VipReturnStatsTable.Lookup(vipAddrKey(testVIP4), &stats); err == nil {
		t.Errorf("vip_return_stats row created by an IPv6 packet: %+v", stats)
	}
}

// TestEdgeLB_IPv4NoFragmentationNeededToSpecialSources covers RFC 1122 3.2.2:
// a too-big Don't Fragment packet from an unspecified, loopback, multicast or
// broadcast source is dropped without an ICMP error.
func TestEdgeLB_IPv4NoFragmentationNeededToSpecialSources(t *testing.T) {
	requireRoot(t)
	narrowFabric4(t, []netip.Addr{testUSID})
	objs := loadObjects(t)
	putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, testUSID)

	sources := []string{"0.1.2.3", "127.0.0.1", "224.0.0.1", "255.255.255.255"}
	for _, src := range sources {
		pkt := buildIPv4Packet(t, ipprotoTCP, testVIP4, netip.MustParseAddr(src), 41000, 443,
			make([]byte, fabricMTU-ip4Len-tcpLen), ip4Opts{fragOff: ipDF})
		if ret, _ := runLB(t, objs, pkt); ret != xdpDrop {
			t.Errorf("source %s: verdict = %d, want XDP_DROP (%d)", src, ret, xdpDrop)
		}
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibFragNeeded); got != uint64(len(sources)) {
		t.Errorf("drop_reasons[fib_frag_needed] = %d, want %d", got, len(sources))
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonICMPRateLimited); got != 0 {
		t.Errorf("drop_reasons[icmp_rate_limited] = %d, want 0 (no message attempted)", got)
	}
}

// TestEdgeReturn_IPv4Failures covers an expiring TTL, a reply with no route,
// and a reply from an address that is no VIP, which is not claimed at all.
func TestEdgeReturn_IPv4Failures(t *testing.T) {
	requireRoot(t)
	// A namespace with no IPv4 route at all, so the test host's own default
	// route cannot answer the lookup.
	narrowFabric4(t, nil)
	objs := loadObjects(t)
	if err := objs.VipAddrTable.Put(vipAddrKey(testVIP4), EdgedsrVipAddrValue{Generation: 1}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}

	expiring := buildIPv4Packet(t, ipprotoUDP, testClient4, testVIP4, 53, 41000, nil, ip4Opts{ttl: 1})
	if ret, _ := runReturn(t, objs, expiring); ret != xdpDrop {
		t.Errorf("TTL 1: verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonReturnHopLimit); got != 1 {
		t.Errorf("drop_reasons[return_hop_limit] = %d, want 1", got)
	}

	unroutable := buildIPv4Packet(t, ipprotoUDP, testClient4, testVIP4, 53, 41000, nil, ip4Opts{})
	if ret, _ := runReturn(t, objs, unroutable); ret != xdpDrop {
		t.Errorf("no route: verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	fib := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed) +
		sumPerCPU(t, objs.DropReasons, DropReasonFibUnreachable) + sumPerCPU(t, objs.DropReasons, DropReasonFibNoNeigh)
	if fib != 1 {
		t.Errorf("FIB drops = %d, want 1", fib)
	}

	other := buildIPv4Packet(t, ipprotoUDP, testClient4, netip.MustParseAddr("10.60.0.5"), 53, 41000, nil, ip4Opts{})
	if ret, _ := runReturn(t, objs, other); ret != xdpPass {
		t.Errorf("non-VIP source: verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}

	var stats EdgedsrVipStatsValue
	if err := objs.VipReturnStatsTable.Lookup(vipAddrKey(testVIP4), &stats); err != nil {
		t.Fatalf("lookup vip_return_stats_table: %v", err)
	}
	if stats.Packets != 2 || stats.DroppedPackets != 2 {
		t.Errorf("return stats packets/dropped = %d/%d, want 2/2", stats.Packets, stats.DroppedPackets)
	}
}

// TestEdgeLB_IPv4ChainsUnclaimedTraffic covers the dispatcher: an IPv4 packet
// to no VIP, such as a NAT64 reply to a masquerade address on the shared
// uplink, reaches the egress slot, and a claimed IPv4 VIP packet does not.
func TestEdgeLB_IPv4ChainsUnclaimedTraffic(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	installChainStub(t, objs, roleGatewayLB|roleEgress)
	if err := objs.VipTable.Put(vipKey(ipprotoUDP, 53, testVIP4), EdgedsrVipValue{BackendCount: 0}); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}

	tests := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"NAT64 reply to a masquerade address is chained",
			buildIPv4Packet(t, ipprotoUDP, netip.MustParseAddr("203.0.113.40"), testClient4, 53, 41000, nil,
				ip4Opts{}), chainStubVerdict},
		{"another port on the VIP is chained",
			buildIPv4Packet(t, ipprotoUDP, testVIP4, testClient4, 41000, 54, nil, ip4Opts{}), chainStubVerdict},
		{"ICMP to the VIP is chained",
			func() []byte {
				p := buildIPv4Packet(t, ipprotoUDP, testVIP4, testClient4, 41000, 53, nil, ip4Opts{})
				p[ethLen+9] = ipprotoICMP
				return p
			}(), chainStubVerdict},
		{"claimed IPv4 VIP is not chained",
			buildIPv4Packet(t, ipprotoUDP, testVIP4, testClient4, 41000, 53, nil, ip4Opts{}), xdpDrop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if ret, _ := runLB(t, objs, tt.pkt); ret != tt.want {
				t.Errorf("verdict = %d, want %d", ret, tt.want)
			}
		})
	}
}
