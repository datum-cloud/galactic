// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// Tests for vip_xlat4, the IPv4 vip_xlat_table rewrite: usid_ingress
// rewriting a client's packet to an IPv4 VIP to the backend chosen by the
// outer destination's slot, and usid_egress rewriting the backend's reply back
// to the VIP and sending it out the fabric uplink. IPv4 rows key and rewrite
// to IPv4-mapped addresses.
//
// Every rewrite is checked against an independent full recompute of both the
// IPv4 header checksum and the TCP or UDP checksum.

var (
	xlat4Client  = netip.MustParseAddr("198.51.100.7")
	xlat4VIP     = netip.MustParseAddr("203.0.113.10")
	xlat4Backend = netip.MustParseAddr("10.60.0.5")
)

const (
	xlat4ClientPort  = 40123
	xlat4VIPPort     = 443
	xlat4BackendPort = 8443
	xlat4Slot        = 0x4A4A
)

// l4Header builds a TCP (20-byte header) or UDP header from sport to dport
// followed by payload, with its checksum field zero.
func l4Header(proto byte, sport, dport uint16, payload []byte) []byte {
	hdrLen := 8
	if proto == ipProtoTCP {
		hdrLen = 20
	}
	l4 := make([]byte, hdrLen, hdrLen+len(payload))
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	if proto == ipProtoTCP {
		binary.BigEndian.PutUint32(l4[4:8], 1)
		l4[12] = 5 << 4
		l4[13] = tcpFlagACK
		binary.BigEndian.PutUint16(l4[14:16], 65535)
	} else {
		binary.BigEndian.PutUint16(l4[4:6], uint16(hdrLen+len(payload)))
	}
	return append(l4, payload...)
}

// l4CsumOffset is the checksum field's offset in a TCP or UDP header.
func l4CsumOffset(proto byte) int {
	if proto == ipProtoTCP {
		return 16
	}
	return 6
}

// l4Sum4 is the one's-complement sum of the IPv4 pseudo-header and l4.
func l4Sum4(proto byte, src, dst netip.Addr, l4 []byte) uint32 {
	sum := onesComplementSum(0, src.AsSlice())
	sum = onesComplementSum(sum, dst.AsSlice())
	sum += uint32(proto) + uint32(len(l4))
	return onesComplementSum(sum, l4)
}

// setL4Checksum4 fills in l4's checksum for src and dst. A UDP checksum that
// computes to zero is sent as 0xFFFF, zero meaning none.
func setL4Checksum4(proto byte, src, dst netip.Addr, l4 []byte) {
	off := l4CsumOffset(proto)
	l4[off], l4[off+1] = 0, 0
	csum := ^fold(l4Sum4(proto, src, dst, l4))
	if proto == ipProtoUDP && csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(l4[off:off+2], csum)
}

// ip4Datagram returns an IPv4 header, with ipOptions (a multiple of 4 bytes),
// fragOff, ID id and a correct header checksum, carrying l4.
func ip4Datagram(proto byte, src, dst netip.Addr, ipOptions []byte, fragOff, id uint16, l4 []byte) []byte {
	ihl := 20 + len(ipOptions)
	hdr := make([]byte, 20, ihl+len(l4))
	hdr[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(ihl+len(l4)))
	binary.BigEndian.PutUint16(hdr[4:6], id)
	binary.BigEndian.PutUint16(hdr[6:8], fragOff)
	hdr[8] = 64
	hdr[9] = proto
	copy(hdr[12:16], src.AsSlice())
	copy(hdr[16:20], dst.AsSlice())
	hdr = append(hdr, ipOptions...)
	binary.BigEndian.PutUint16(hdr[10:12], ^fold(onesComplementSum(0, hdr)))
	return append(hdr, l4...)
}

// encapsulate4 wraps an IPv4 packet in an Ethernet and outer IPv6 header
// toward outerDst with Next Header 4, as galactic-gateway sends it.
func encapsulate4(outerDst netip.Addr, inner []byte) []byte {
	outer := make([]byte, ip6HeaderLen, ip6HeaderLen+len(inner))
	outer[0] = 0x60
	binary.BigEndian.PutUint16(outer[4:6], uint16(len(inner)))
	outer[6] = 4
	outer[7] = 64
	copy(outer[8:24], netip.MustParseAddr("2001:db8:ff01:1002::").AsSlice())
	copy(outer[24:40], outerDst.AsSlice())
	return withEth(0x86DD, append(outer, inner...))
}

// ip4View is one parsed IPv4 TCP or UDP packet.
type ip4View struct {
	src, dst     netip.Addr
	sport, dport uint16
	l4csum       uint16
	hdrValid     bool
	l4Valid      bool
}

// parseIP4 parses the IPv4 packet at the start of l3 and checks both its
// checksums. A zero UDP checksum counts as valid, zero meaning none.
func parseIP4(t *testing.T, l3 []byte) ip4View {
	t.Helper()
	if len(l3) < 20 || l3[0]>>4 != 4 {
		t.Fatalf("not an IPv4 packet: % x", l3)
	}
	ihl := int(l3[0]&0x0F) * 4
	total := int(binary.BigEndian.Uint16(l3[2:4]))
	if total > len(l3) || total < ihl+8 {
		t.Fatalf("total length %d does not fit a %d-byte packet with a %d-byte header", total, len(l3), ihl)
	}
	proto := l3[9]
	src, _ := netip.AddrFromSlice(l3[12:16])
	dst, _ := netip.AddrFromSlice(l3[16:20])
	l4 := l3[ihl:total]
	off := l4CsumOffset(proto)
	v := ip4View{
		src: src, dst: dst,
		sport:    binary.BigEndian.Uint16(l4[0:2]),
		dport:    binary.BigEndian.Uint16(l4[2:4]),
		l4csum:   binary.BigEndian.Uint16(l4[off : off+2]),
		hdrValid: fold(onesComplementSum(0, l3[:ihl])) == 0xFFFF,
	}
	v.l4Valid = (proto == ipProtoUDP && v.l4csum == 0) || fold(l4Sum4(proto, src, dst, l4)) == 0xFFFF
	return v
}

// putVIP4Row writes an IPv4 vip_xlat_table row the way vipxlatmap writes one:
// key and value addresses in IPv4-mapped form.
func putVIP4Row(
	t *testing.T, objs *UsidObjects, block uint64, argument, slot uint16, proto uint8, direction uint8,
	keyAddr netip.Addr, keyPort uint16, valAddr netip.Addr, valPort uint16,
) {
	t.Helper()
	key := UsidVipXlatKey{
		Block: block, Argument: argument, Slot: slot, Proto: proto, Direction: direction,
		Port: bswap16(keyPort), Addr: keyAddr.As16(),
	}
	if err := objs.VipXlatTable.Put(key, UsidVipXlatValue{Addr: valAddr.As16(), Port: bswap16(valPort)}); err != nil {
		t.Fatalf("populate vip_xlat_table: %v", err)
	}
}

// vip4IngressFixture registers a local End.DT46 VRF with no routes and the
// IPv4 ingress rows for TCP and UDP bindings of xlat4VIP:xlat4VIPPort to
// xlat4Backend:xlat4BackendPort under xlat4Slot. It returns the objects and
// the uSID carrying that slot.
func vip4IngressFixture(t *testing.T) (*UsidObjects, testUSID) {
	t.Helper()
	requireRoot(t)
	objs := loadObjects(t)
	usid := testUSID{
		block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46,
		argument: 0x705, slot: xlat4Slot,
	}
	setUpVIPIngress(t, objs, usid)
	for _, proto := range []uint8{ipProtoTCP, ipProtoUDP} {
		putVIP4Row(t, objs, usid.block, usid.argument, usid.slot, proto, usidVIPXlatDirIngress,
			xlat4VIP, xlat4VIPPort, xlat4Backend, xlat4BackendPort)
	}
	return objs, usid
}

// runIngress4 sends an encapsulated IPv4 packet through usid_ingress, which
// stops at the FIB lookup of a VRF with no routes, and returns the
// decapsulated packet from its IP header on.
func runIngress4(t *testing.T, objs *UsidObjects, outerDst netip.Addr, inner []byte) []byte {
	t.Helper()
	ret, out, err := objs.UsidIngress.Test(encapsulate4(outerDst, inner))
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("verdict = %d, want TC_ACT_SHOT (%d) at the FIB lookup", ret, tcActShot)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonMalformedInner); got != 0 {
		t.Fatalf("drop_reasons[malformed_inner] = %d, want 0: the rewrite must not fail", got)
	}
	return out[ethHeaderLen:]
}

// clientDatagram builds the client's packet to the VIP.
func clientDatagram(proto byte, ipOptions []byte, fragOff uint16, payload []byte) []byte {
	l4 := l4Header(proto, xlat4ClientPort, xlat4VIPPort, payload)
	setL4Checksum4(proto, xlat4Client, xlat4VIP, l4)
	return ip4Datagram(proto, xlat4Client, xlat4VIP, ipOptions, fragOff, 0x1234, l4)
}

// TestUsidIngress_VIPXlat4RewritesToBackend: a client's TCP or UDP packet to
// an IPv4 VIP leaves for the backend's address and port, with the client's
// source untouched and both checksums correct, with and without IP options.
func TestUsidIngress_VIPXlat4RewritesToBackend(t *testing.T) {
	timestamp := []byte{68, 12, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0} // RFC 791 timestamp option, room for two
	for _, tc := range []struct {
		name      string
		proto     byte
		ipOptions []byte
	}{
		{"TCPNoOptions", ipProtoTCP, nil},
		{"UDPNoOptions", ipProtoUDP, nil},
		{"TCPWithOptions", ipProtoTCP, timestamp},
		{"UDPWithOptions", ipProtoUDP, []byte{1, 1, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, usid := vip4IngressFixture(t)
			in := clientDatagram(tc.proto, tc.ipOptions, 0, []byte("hello, backend"))

			out := runIngress4(t, objs, usid.addr(t), in)
			got := parseIP4(t, out)
			if got.dst != xlat4Backend || got.dport != xlat4BackendPort {
				t.Errorf("destination = %s:%d, want %s:%d", got.dst, got.dport, xlat4Backend, xlat4BackendPort)
			}
			if got.src != xlat4Client || got.sport != xlat4ClientPort {
				t.Errorf("source = %s:%d, want the client's own %s:%d", got.src, got.sport, xlat4Client, xlat4ClientPort)
			}
			if !got.hdrValid {
				t.Error("IPv4 header checksum is wrong after the rewrite")
			}
			if !got.l4Valid {
				t.Errorf("L4 checksum %#04x is wrong after the rewrite", got.l4csum)
			}
			ihl := 20 + len(tc.ipOptions)
			if !bytes.Equal(out[20:ihl], tc.ipOptions) {
				t.Errorf("IP options changed: % x, want % x", out[20:ihl], tc.ipOptions)
			}
		})
	}
}

// TestUsidIngress_VIPXlat4ChecksumEdges: rewrites whose incremental checksum
// updates land on the one's-complement edges still verify. A UDP checksum that
// would compute to zero is sent as 0xFFFF, a zero UDP checksum (none) stays
// zero, and a TCP checksum and an IPv4 header checksum that land on zero are
// correct.
func TestUsidIngress_VIPXlat4ChecksumEdges(t *testing.T) {
	// payloadFor returns a 2-byte payload whose post-rewrite L4 checksum is
	// want, found by search.
	payloadFor := func(proto byte, want uint16) []byte {
		for w := range 1 << 16 {
			payload := []byte{byte(w >> 8), byte(w)}
			l4 := l4Header(proto, xlat4ClientPort, xlat4BackendPort, payload)
			if ^fold(l4Sum4(proto, xlat4Client, xlat4Backend, l4)) == want {
				return payload
			}
		}
		t.Fatalf("no payload gives checksum %#04x", want)
		return nil
	}

	t.Run("UDPResultZeroBecomesFFFF", func(t *testing.T) {
		objs, usid := vip4IngressFixture(t)
		out := runIngress4(t, objs, usid.addr(t), clientDatagram(ipProtoUDP, nil, 0, payloadFor(ipProtoUDP, 0)))
		if got := parseIP4(t, out); got.l4csum != 0xFFFF || !got.l4Valid {
			t.Errorf("UDP checksum = %#04x (valid %v), want 0xffff", got.l4csum, got.l4Valid)
		}
	})

	t.Run("UDPNoChecksumStaysZero", func(t *testing.T) {
		objs, usid := vip4IngressFixture(t)
		l4 := l4Header(ipProtoUDP, xlat4ClientPort, xlat4VIPPort, []byte("no checksum"))
		in := ip4Datagram(ipProtoUDP, xlat4Client, xlat4VIP, nil, 0, 0x1234, l4)
		got := parseIP4(t, runIngress4(t, objs, usid.addr(t), in))
		if got.l4csum != 0 || got.dst != xlat4Backend {
			t.Errorf("UDP checksum = %#04x, destination %s; want 0 and %s", got.l4csum, got.dst, xlat4Backend)
		}
	})

	t.Run("TCPResultZero", func(t *testing.T) {
		objs, usid := vip4IngressFixture(t)
		got := parseIP4(t, runIngress4(t, objs, usid.addr(t), clientDatagram(ipProtoTCP, nil, 0, payloadFor(ipProtoTCP, 0))))
		if !got.l4Valid {
			t.Errorf("TCP checksum %#04x is wrong", got.l4csum)
		}
	})

	t.Run("HeaderChecksumResultZero", func(t *testing.T) {
		objs, usid := vip4IngressFixture(t)
		l4 := l4Header(ipProtoUDP, xlat4ClientPort, xlat4VIPPort, []byte("id"))
		setL4Checksum4(ipProtoUDP, xlat4Client, xlat4VIP, l4)
		var in []byte
		for id := range 1 << 16 {
			after := ip4Datagram(ipProtoUDP, xlat4Client, xlat4Backend, nil, 0, uint16(id), l4)
			if binary.BigEndian.Uint16(after[10:12]) == 0 {
				in = ip4Datagram(ipProtoUDP, xlat4Client, xlat4VIP, nil, 0, uint16(id), l4)
				break
			}
		}
		if in == nil {
			t.Fatal("no IPv4 ID gives a zero header checksum")
		}
		out := runIngress4(t, objs, usid.addr(t), in)
		if got := parseIP4(t, out); !got.hdrValid || !got.l4Valid || got.dst != xlat4Backend {
			t.Errorf("header valid %v, L4 valid %v, destination %s; want both valid and %s",
				got.hdrValid, got.l4Valid, got.dst, xlat4Backend)
		}
	})
}

// TestUsidIngress_VIPXlat4LeavesOtherPacketsAlone: fragments, a destination
// with no row, another port, another slot and an IPv6 packet to the VIP's
// IPv4-mapped address all leave unchanged.
func TestUsidIngress_VIPXlat4LeavesOtherPacketsAlone(t *testing.T) {
	const moreFragments = 0x2000

	otherDst := func() []byte {
		l4 := l4Header(ipProtoTCP, xlat4ClientPort, xlat4VIPPort, []byte("x"))
		dst := netip.MustParseAddr("203.0.113.11")
		setL4Checksum4(ipProtoTCP, xlat4Client, dst, l4)
		return ip4Datagram(ipProtoTCP, xlat4Client, dst, nil, 0, 1, l4)
	}
	otherPort := func() []byte {
		l4 := l4Header(ipProtoTCP, xlat4ClientPort, xlat4VIPPort+1, []byte("x"))
		setL4Checksum4(ipProtoTCP, xlat4Client, xlat4VIP, l4)
		return ip4Datagram(ipProtoTCP, xlat4Client, xlat4VIP, nil, 0, 1, l4)
	}
	for _, tc := range []struct {
		name  string
		inner []byte
		slot  uint16
	}{
		{"FirstFragment", clientDatagram(ipProtoUDP, nil, moreFragments, []byte("part one")), xlat4Slot},
		{"LaterFragment", clientDatagram(ipProtoUDP, nil, 3, []byte("part two")), xlat4Slot},
		{"OtherDestination", otherDst(), xlat4Slot},
		{"OtherPort", otherPort(), xlat4Slot},
		{"OtherSlot", clientDatagram(ipProtoTCP, nil, 0, []byte("x")), 0x1111},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, usid := vip4IngressFixture(t)
			usid.slot = tc.slot
			out := runIngress4(t, objs, usid.addr(t), tc.inner)
			if !bytes.Equal(out[:len(tc.inner)], tc.inner) {
				t.Errorf("packet changed:\n in: % x\nout: % x", tc.inner, out[:len(tc.inner)])
			}
		})
	}

	t.Run("IPv6ToMappedVIP", func(t *testing.T) {
		objs, usid := vip4IngressFixture(t)
		src := netip.MustParseAddr("2001:db8:ffff::1")
		mapped := netip.AddrFrom16(xlat4VIP.As16())
		udp := udpTo(src, mapped, xlat4VIPPort)
		pkt := buildPacketWithUDPInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), src, mapped, udp)
		ret, out, err := objs.UsidIngress.Test(pkt)
		if err != nil {
			t.Fatalf("program test-run: %v", err)
		}
		if ret != tcActShot {
			t.Fatalf("verdict = %d, want TC_ACT_SHOT (%d) at the FIB lookup", ret, tcActShot)
		}
		const daddrOffset = ethHeaderLen + 24
		if got, _ := netip.AddrFromSlice(out[daddrOffset : daddrOffset+16]); got != mapped {
			t.Errorf("IPv6 packet to %s left for %s: an IPv6 packet must never take an IPv4 row", mapped, got)
		}
	})
}

// The uplink MACs the egress fixture publishes.
var (
	xlat4UplinkDMAC = [6]byte{0x02, 0, 0, 0, 0, 0xD1}
	xlat4UplinkSMAC = [6]byte{0x02, 0, 0, 0, 0, 0x51}
)

// vip4EgressFixture registers a tenant attachment with IPv4 egress rows for TCP
// and UDP bindings of xlat4Backend:xlat4BackendPort to xlat4VIP:xlat4VIPPort,
// a configured public uplink, and, when withDefault, an IPv4 default route
// that encapsulates toward an egress shard.
func vip4EgressFixture(t *testing.T, withDefault bool) *UsidObjects {
	t.Helper()
	requireRoot(t)
	objs := loadObjects(t)
	const tableID = 31
	block, argument := uint64(0xFEEDFA), uint16(0x705)
	setUpEgressRouteAttachment(t, objs, block, argument, tableID)
	if err := objs.PublicUplinkTable.Put(uint32(0), UsidPublicUplinkValue{
		LinkIfindex: 1, Dmac: xlat4UplinkDMAC, Smac: xlat4UplinkSMAC,
	}); err != nil {
		t.Fatalf("populate public_uplink_table: %v", err)
	}
	if withDefault {
		if err := objs.EgressRouteTable.Put(egressRouteKey(tableID, egressRouteFamilyINET4, netip.IPv4Unspecified(), 0),
			UsidEgressRouteValue{
				Sid: netip.MustParseAddr("2001:db8:ff01:2002:e705::").As16(), LinkIfindex: 1,
				Dmac: [6]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, Smac: [6]byte{0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB},
			}); err != nil {
			t.Fatalf("populate egress_route_table: %v", err)
		}
		setUpNodeSIDBase(t, objs, netip.MustParseAddr("2001:db8:ff01:1:e000::"), argument)
	}
	for _, proto := range []uint8{ipProtoTCP, ipProtoUDP} {
		putVIP4Row(t, objs, block, argument, 0, proto, usidVIPXlatDirEgress,
			xlat4Backend, xlat4BackendPort, xlat4VIP, xlat4VIPPort)
	}
	return objs
}

// backendReply builds the backend's reply to the client from src:sport.
func backendReply(proto byte, src netip.Addr, sport uint16, ipOptions []byte, fragOff uint16, payload []byte) []byte {
	l4 := l4Header(proto, sport, xlat4ClientPort, payload)
	setL4Checksum4(proto, src, xlat4Client, l4)
	return withEth(0x0800, ip4Datagram(proto, src, xlat4Client, ipOptions, fragOff, 0x4321, l4))
}

// TestUsidEgress_VIPXlat4RewritesReplyToVIP: the backend's TCP or UDP reply
// leaves from the VIP's address and port, unencapsulated, out the public
// uplink, with both checksums correct, and even where an IPv4 default would
// otherwise send the VRF's traffic to an egress shard.
func TestUsidEgress_VIPXlat4RewritesReplyToVIP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		proto       byte
		ipOptions   []byte
		withDefault bool
	}{
		{"TCPNoOptions", ipProtoTCP, nil, false},
		{"UDPNoOptions", ipProtoUDP, nil, false},
		{"TCPWithOptions", ipProtoTCP, []byte{1, 1, 1, 0, 1, 1, 1, 0}, false},
		{"UDPPastShardDefault", ipProtoUDP, nil, true},
		{"TCPPastShardDefault", ipProtoTCP, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := vip4EgressFixture(t, tc.withDefault)
			pkt := backendReply(tc.proto, xlat4Backend, xlat4BackendPort, tc.ipOptions, 0, []byte("hello, client"))

			ret, out, err := objs.UsidEgress.Test(pkt)
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			if ret != tcActRedirect {
				t.Fatalf("verdict = %d, want TC_ACT_REDIRECT (%d) out the public uplink", ret, tcActRedirect)
			}
			if len(out) != len(pkt) {
				t.Fatalf("output length = %d, want %d: the reply must leave unencapsulated", len(out), len(pkt))
			}
			if !bytes.Equal(out[0:6], xlat4UplinkDMAC[:]) || !bytes.Equal(out[6:12], xlat4UplinkSMAC[:]) {
				t.Errorf("MACs = % x / % x, want the public uplink's", out[0:6], out[6:12])
			}
			got := parseIP4(t, out[ethHeaderLen:])
			if got.src != xlat4VIP || got.sport != xlat4VIPPort {
				t.Errorf("source = %s:%d, want %s:%d", got.src, got.sport, xlat4VIP, xlat4VIPPort)
			}
			if got.dst != xlat4Client || got.dport != xlat4ClientPort {
				t.Errorf("destination = %s:%d, want the client's %s:%d", got.dst, got.dport, xlat4Client, xlat4ClientPort)
			}
			if !got.hdrValid || !got.l4Valid {
				t.Errorf("header checksum valid %v, L4 checksum %#04x valid %v; want both valid",
					got.hdrValid, got.l4csum, got.l4Valid)
			}
		})
	}
}

// TestUsidEgress_VIPXlat4ClampsSYNACK: the backend's SYN-ACK on an IPv4 VIP
// is clamped to the IPv4 limit before it leaves, as on an IPv6 VIP, with the
// checksum still correct after both rewrites.
func TestUsidEgress_VIPXlat4ClampsSYNACK(t *testing.T) {
	objs := vip4EgressFixture(t, false)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	seg := tcpSegment(tcpFlagSYN|tcpFlagACK, linuxSYNOptions(1460), 0)
	binary.BigEndian.PutUint16(seg[0:2], xlat4BackendPort)
	binary.BigEndian.PutUint16(seg[2:4], xlat4ClientPort)
	setTCPChecksum(seg, xlat4Backend, xlat4Client)
	pkt := withEth(0x0800, ip4Datagram(ipProtoTCP, xlat4Backend, xlat4Client, nil, 0, 1, seg))

	ret, out, err := objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActRedirect {
		t.Fatalf("verdict = %d, want TC_ACT_REDIRECT (%d)", ret, tcActRedirect)
	}
	l3 := out[ethHeaderLen:]
	got := parseIP4(t, l3)
	if got.src != xlat4VIP || !got.hdrValid || !got.l4Valid {
		t.Errorf("source %s, header valid %v, TCP valid %v; want %s and both valid",
			got.src, got.hdrValid, got.l4Valid, xlat4VIP)
	}
	if mss, ok := mssOf(l3[20:]); !ok || mss != testMSSLimitV4 {
		t.Errorf("MSS = %d (present %v), want %d", mss, ok, testMSSLimitV4)
	}
}

// TestUsidEgress_VIPXlat4LeavesOtherPacketsAlone: a fragment of the reply, a
// workload that is not the backend, the backend on another port, and an IPv6
// packet from the backend's IPv4-mapped address are not rewritten and not
// sent out the public uplink.
func TestUsidEgress_VIPXlat4LeavesOtherPacketsAlone(t *testing.T) {
	const moreFragments = 0x2000
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"FirstFragment", backendReply(ipProtoUDP, xlat4Backend, xlat4BackendPort, nil, moreFragments, []byte("a"))},
		{"LaterFragment", backendReply(ipProtoUDP, xlat4Backend, xlat4BackendPort, nil, 7, []byte("b"))},
		{"NotTheBackend", backendReply(ipProtoTCP, netip.MustParseAddr("10.60.0.6"), xlat4BackendPort, nil, 0, nil)},
		{"OtherPort", backendReply(ipProtoTCP, xlat4Backend, xlat4BackendPort+1, nil, 0, nil)},
		{"IPv6FromMappedBackend", buildPlainV6PacketWithL4Ports(t, netip.AddrFrom16(xlat4Backend.As16()),
			netip.MustParseAddr("2001:db8:0:13::1"), xlat4BackendPort, xlat4ClientPort)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := vip4EgressFixture(t, false)
			ret, out, err := objs.UsidEgress.Test(tc.pkt)
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			if ret == tcActRedirect {
				t.Errorf("verdict = TC_ACT_REDIRECT, want the packet left to ordinary routing")
			}
			if !bytes.Equal(out, tc.pkt) {
				t.Errorf("packet changed:\n in: % x\nout: % x", tc.pkt, out)
			}
		})
	}
}
