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

// Tests for the IPv4 VIP translation: usid_ingress translating a client's
// IPv4 packet to an IPv4 VIP into the IPv6 packet its backend receives
// (vip_siit_ingress), and usid_egress translating the backend's IPv6 reply
// back to IPv4 from the VIP and sending it out the fabric uplink
// (vip_siit_egress). The client appears to the backend as 64:ff9b::<client>.
//
// Every translation is checked against checksums computed here from the
// translated packet alone: the IPv4 header checksum, and the TCP or UDP
// checksum over each family's own pseudo-header.

var (
	xlat4Client       = netip.MustParseAddr("198.51.100.7")
	xlat4ClientMapped = netip.MustParseAddr("64:ff9b::c633:6407") // 64:ff9b::198.51.100.7
	xlat4VIP          = netip.MustParseAddr("203.0.113.10")
	xlat4VIP6         = netip.MustParseAddr("2001:db8:1::10")
	xlat4Backend      = netip.MustParseAddr("fd20:60::5")
)

const (
	xlat4ClientPort  = 40123
	xlat4VIPPort     = 443
	xlat4BackendPort = 8443
	xlat4Slot        = 0x4A4A
	xlat4TOS         = 0xB8 // DSCP EF
	xlat4TTL         = 57

	usidVIPXlatDirEgressXlat = 2
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

// l4Sum is the one's-complement sum of l4 and its pseudo-header, IPv4 or IPv6
// by the family of src and dst. Length and protocol add the same in both.
func l4Sum(proto byte, src, dst netip.Addr, l4 []byte) uint32 {
	sum := onesComplementSum(0, src.AsSlice())
	sum = onesComplementSum(sum, dst.AsSlice())
	sum += uint32(proto) + uint32(len(l4))
	return onesComplementSum(sum, l4)
}

// setL4Checksum fills in l4's checksum for src and dst. A UDP checksum that
// computes to zero is sent as 0xFFFF, zero meaning none.
func setL4Checksum(proto byte, src, dst netip.Addr, l4 []byte) {
	off := l4CsumOffset(proto)
	l4[off], l4[off+1] = 0, 0
	csum := ^fold(l4Sum(proto, src, dst, l4))
	if proto == ipProtoUDP && csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(l4[off:off+2], csum)
}

// ip4Datagram returns an IPv4 header with TOS tos, TTL xlat4TTL, ipOptions (a
// multiple of 4 bytes), fragOff, ID id and a correct header checksum,
// carrying l4.
func ip4Datagram(proto byte, src, dst netip.Addr, tos byte, ipOptions []byte, fragOff, id uint16, l4 []byte) []byte {
	ihl := 20 + len(ipOptions)
	hdr := make([]byte, 20, ihl+len(l4))
	hdr[0] = 0x40 | byte(ihl/4)
	hdr[1] = tos
	binary.BigEndian.PutUint16(hdr[2:4], uint16(ihl+len(l4)))
	binary.BigEndian.PutUint16(hdr[4:6], id)
	binary.BigEndian.PutUint16(hdr[6:8], fragOff)
	hdr[8] = xlat4TTL
	hdr[9] = proto
	copy(hdr[12:16], src.AsSlice())
	copy(hdr[16:20], dst.AsSlice())
	hdr = append(hdr, ipOptions...)
	binary.BigEndian.PutUint16(hdr[10:12], ^fold(onesComplementSum(0, hdr)))
	return append(hdr, l4...)
}

// ip6Datagram returns an IPv6 header with traffic class tc, flow label
// flowLabel and hop limit xlat4TTL, carrying l4 under next header nexthdr.
func ip6Datagram(nexthdr byte, src, dst netip.Addr, tc byte, flowLabel uint32, l4 []byte) []byte {
	hdr := make([]byte, 40, 40+len(l4))
	binary.BigEndian.PutUint32(hdr[0:4], 6<<28|uint32(tc)<<20|flowLabel&0xFFFFF)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(l4)))
	hdr[6] = nexthdr
	hdr[7] = xlat4TTL
	copy(hdr[8:24], src.AsSlice())
	copy(hdr[24:40], dst.AsSlice())
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

// l4View is the transport header of one parsed packet.
type l4View struct {
	sport, dport uint16
	l4csum       uint16
	l4Valid      bool
	payload      []byte
}

// parseL4 parses l4 as a TCP or UDP header and checks its checksum against
// src and dst. A zero UDP checksum counts as valid only when zeroOK.
func parseL4(t *testing.T, proto byte, src, dst netip.Addr, l4 []byte, zeroOK bool) l4View {
	t.Helper()
	off := l4CsumOffset(proto)
	if len(l4) < off+2 {
		t.Fatalf("L4 header truncated: % x", l4)
	}
	hdrLen := 8
	if proto == ipProtoTCP {
		hdrLen = int(l4[12]>>4) * 4
	}
	v := l4View{
		sport:   binary.BigEndian.Uint16(l4[0:2]),
		dport:   binary.BigEndian.Uint16(l4[2:4]),
		l4csum:  binary.BigEndian.Uint16(l4[off : off+2]),
		payload: l4[hdrLen:],
	}
	v.l4Valid = (proto == ipProtoUDP && v.l4csum == 0 && zeroOK) || fold(l4Sum(proto, src, dst, l4)) == 0xFFFF
	return v
}

// ip6View is one parsed IPv6 TCP or UDP packet.
type ip6View struct {
	l4View
	src, dst     netip.Addr
	trafficClass byte
	flowLabel    uint32
	hopLimit     byte
	nexthdr      byte
}

// parseIP6 parses the IPv6 packet at the start of l3, which must be exactly
// as long as its payload length says, and checks its L4 checksum. A zero UDP
// checksum is invalid in IPv6.
func parseIP6(t *testing.T, l3 []byte) ip6View {
	t.Helper()
	if len(l3) < 40 || l3[0]>>4 != 6 {
		t.Fatalf("not an IPv6 packet: % x", l3)
	}
	if got, want := len(l3), 40+int(binary.BigEndian.Uint16(l3[4:6])); got != want {
		t.Fatalf("packet is %d bytes, but its payload length makes it %d", got, want)
	}
	word := binary.BigEndian.Uint32(l3[0:4])
	src, _ := netip.AddrFromSlice(l3[8:24])
	dst, _ := netip.AddrFromSlice(l3[24:40])
	return ip6View{
		l4View:       parseL4(t, l3[6], src, dst, l3[40:], false),
		src:          src,
		dst:          dst,
		trafficClass: byte(word >> 20),
		flowLabel:    word & 0xFFFFF,
		hopLimit:     l3[7],
		nexthdr:      l3[6],
	}
}

// ip4View is one parsed IPv4 TCP or UDP packet.
type ip4View struct {
	l4View
	src, dst netip.Addr
	ihl      int
	tos      byte
	ttl      byte
	id       uint16
	fragOff  uint16
	hdrValid bool
}

// parseIP4 parses the IPv4 packet at the start of l3, which must be exactly
// as long as its total length says, and checks both its checksums. A zero
// UDP checksum is valid in IPv4, meaning none.
func parseIP4(t *testing.T, l3 []byte) ip4View {
	t.Helper()
	if len(l3) < 20 || l3[0]>>4 != 4 {
		t.Fatalf("not an IPv4 packet: % x", l3)
	}
	ihl := int(l3[0]&0x0F) * 4
	if got, want := len(l3), int(binary.BigEndian.Uint16(l3[2:4])); got != want {
		t.Fatalf("packet is %d bytes, but its total length says %d", got, want)
	}
	src, _ := netip.AddrFromSlice(l3[12:16])
	dst, _ := netip.AddrFromSlice(l3[16:20])
	return ip4View{
		l4View:   parseL4(t, l3[9], src, dst, l3[ihl:], true),
		src:      src,
		dst:      dst,
		ihl:      ihl,
		tos:      l3[1],
		ttl:      l3[8],
		id:       binary.BigEndian.Uint16(l3[4:6]),
		fragOff:  binary.BigEndian.Uint16(l3[6:8]),
		hdrValid: fold(onesComplementSum(0, l3[:ihl])) == 0xFFFF,
	}
}

// putXlatRow writes one vip_xlat_table row. An IPv4 address is stored
// IPv4-mapped, the way vipxlatmap stores an IPv4 VIP.
func putXlatRow(
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

// vip4IngressFixture registers a local End.DT46 VRF with no routes and, for
// TCP and UDP, the ingress rows of two VIPs served by the same backend socket
// xlat4Backend:xlat4BackendPort under xlat4Slot: the IPv4 VIP
// xlat4VIP:xlat4VIPPort and the IPv6 VIP xlat4VIP6:xlat4VIPPort. It returns
// the objects and the uSID carrying that slot.
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
		for _, vip := range []netip.Addr{xlat4VIP, xlat4VIP6} {
			putXlatRow(t, objs, usid.block, usid.argument, usid.slot, proto, usidVIPXlatDirIngress,
				vip, xlat4VIPPort, xlat4Backend, xlat4BackendPort)
		}
	}
	return objs, usid
}

// runIngressXlat4 sends an encapsulated packet through usid_ingress, which stops at
// the FIB lookup of a VRF with no routes, and returns the decapsulated frame
// and the drop reason counters that moved.
func runIngressXlat4(t *testing.T, objs *UsidObjects, pkt []byte) []byte {
	t.Helper()
	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("verdict = %d, want TC_ACT_SHOT (%d) at the FIB lookup", ret, tcActShot)
	}
	for _, reason := range []uint32{
		DropReasonMalformedInner, DropReasonVIPXlatFailed, DropReasonVIPIPv4Fragment, DropReasonVIPUDPNoChecksum,
	} {
		if got := sumPerCPU(t, objs.DropReasons, reason); got != 0 {
			t.Fatalf("drop_reasons[%s] = %d, want 0", DropReasonNames[reason], got)
		}
	}
	return out
}

// clientDatagram builds the client's checksummed packet to dst:dport.
func clientDatagram(proto byte, dst netip.Addr, dport uint16, ipOptions []byte, fragOff uint16, payload []byte) []byte {
	l4 := l4Header(proto, xlat4ClientPort, dport, payload)
	setL4Checksum(proto, xlat4Client, dst, l4)
	return ip4Datagram(proto, xlat4Client, dst, xlat4TOS, ipOptions, fragOff, 0x1234, l4)
}

// TestUsidIngress_VIPXlat4TranslatesToIPv6Backend: a client's TCP or UDP
// packet to an IPv4 VIP reaches the backend as IPv6, from the client's
// 64:ff9b:: address to the backend's address and port, with the TOS as its
// traffic class, the TTL less one as its hop limit, no flow label, its IP options
// dropped, its payload intact and a valid checksum.
func TestUsidIngress_VIPXlat4TranslatesToIPv6Backend(t *testing.T) {
	timestamp := []byte{68, 12, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0} // RFC 791 timestamp option, room for two
	payload := []byte("hello, backend")
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
			in := clientDatagram(tc.proto, xlat4VIP, xlat4VIPPort, tc.ipOptions, 0, payload)

			out := runIngressXlat4(t, objs, encapsulate4(usid.addr(t), in))
			if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
				t.Errorf("EtherType = %#04x, want 0x86dd", got)
			}
			got := parseIP6(t, out[ethHeaderLen:])
			if got.dst != xlat4Backend || got.dport != xlat4BackendPort {
				t.Errorf("destination = %s:%d, want %s:%d", got.dst, got.dport, xlat4Backend, xlat4BackendPort)
			}
			if got.src != xlat4ClientMapped || got.sport != xlat4ClientPort {
				t.Errorf("source = %s:%d, want %s:%d", got.src, got.sport, xlat4ClientMapped, xlat4ClientPort)
			}
			if got.nexthdr != tc.proto || got.trafficClass != xlat4TOS || got.flowLabel != 0 || got.hopLimit != xlat4TTL-1 {
				t.Errorf("next header %d, traffic class %#02x, flow label %#x, hop limit %d; want %d, %#02x, 0, %d",
					got.nexthdr, got.trafficClass, got.flowLabel, got.hopLimit, tc.proto, xlat4TOS, xlat4TTL-1)
			}
			if !got.l4Valid {
				t.Errorf("L4 checksum %#04x is wrong after the translation", got.l4csum)
			}
			if !bytes.Equal(got.payload, payload) {
				t.Errorf("payload = %q, want %q", got.payload, payload)
			}
		})
	}
}

// TestUsidIngress_VIPXlat4ChecksumEdges: a translated UDP checksum that
// computes to zero is sent as 0xFFFF, and a TCP checksum that lands on zero
// is correct.
func TestUsidIngress_VIPXlat4ChecksumEdges(t *testing.T) {
	// payloadFor returns a 2-byte payload whose translated L4 checksum is want.
	payloadFor := func(proto byte, want uint16) []byte {
		for w := range 1 << 16 {
			payload := []byte{byte(w >> 8), byte(w)}
			l4 := l4Header(proto, xlat4ClientPort, xlat4BackendPort, payload)
			if ^fold(l4Sum(proto, xlat4ClientMapped, xlat4Backend, l4)) == want {
				return payload
			}
		}
		t.Fatalf("no payload gives checksum %#04x", want)
		return nil
	}
	for _, tc := range []struct {
		name  string
		proto byte
		want  uint16
	}{
		{"UDPResultZeroBecomesFFFF", ipProtoUDP, 0xFFFF},
		{"TCPResultZero", ipProtoTCP, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, usid := vip4IngressFixture(t)
			in := clientDatagram(tc.proto, xlat4VIP, xlat4VIPPort, nil, 0, payloadFor(tc.proto, 0))
			got := parseIP6(t, runIngressXlat4(t, objs, encapsulate4(usid.addr(t), in))[ethHeaderLen:])
			if got.l4csum != tc.want || !got.l4Valid {
				t.Errorf("checksum = %#04x (valid %v), want %#04x", got.l4csum, got.l4Valid, tc.want)
			}
		})
	}
}

// TestUsidIngress_VIPXlat4DropsUntranslatable: a fragment for a VIP backend,
// first or later, a UDP datagram to the VIP with no checksum, a packet whose
// TTL translation would exhaust, and a packet whose row names an IPv4 backend,
// which an IPv6-only workload cannot receive, are dropped and counted under
// their own reasons, never delivered.
func TestUsidIngress_VIPXlat4DropsUntranslatable(t *testing.T) {
	const moreFragments = 0x2000
	noChecksum := func() []byte {
		l4 := l4Header(ipProtoUDP, xlat4ClientPort, xlat4VIPPort, []byte("no checksum"))
		return ip4Datagram(ipProtoUDP, xlat4Client, xlat4VIP, 0, nil, 0, 0x1234, l4)
	}
	for _, tc := range []struct {
		name   string
		inner  []byte
		reason uint32
	}{
		{"FirstFragment", clientDatagram(ipProtoUDP, xlat4VIP, xlat4VIPPort, nil, moreFragments, []byte("one")),
			DropReasonVIPIPv4Fragment},
		{"LaterFragment", clientDatagram(ipProtoUDP, xlat4VIP, xlat4VIPPort, nil, 3, []byte("two")),
			DropReasonVIPIPv4Fragment},
		{"UDPNoChecksum", noChecksum(), DropReasonVIPUDPNoChecksum},
		{"TTLOne", withTTL(clientDatagram(ipProtoTCP, xlat4VIP, xlat4VIPPort, nil, 0, []byte("ttl")), 1),
			DropReasonVIPTTLExceeded},
		{"TTLZero", withTTL(clientDatagram(ipProtoUDP, xlat4VIP, xlat4VIPPort, nil, 0, []byte("ttl")), 0),
			DropReasonVIPTTLExceeded},
		{"IPv4BackendRow", clientDatagram(ipProtoTCP, xlat4VIP, nativeVIPPort, nil, 0, []byte("native")),
			DropReasonVIPIPv4Backend},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, usid := vip4IngressFixture(t)
			// The row a router predating translation writes: an IPv4 VIP
			// rewritten to an IPv4 backend, both IPv4-mapped.
			putXlatRow(t, objs, usid.block, usid.argument, usid.slot, ipProtoTCP, usidVIPXlatDirIngress,
				xlat4VIP, nativeVIPPort, netip.MustParseAddr("10.60.0.5"), xlat4BackendPort)
			ret, _, err := objs.UsidIngress.Test(encapsulate4(usid.addr(t), tc.inner))
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			if ret != tcActShot {
				t.Fatalf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
			}
			assertOnlyMetricDropReason(t, objs, tc.reason)
		})
	}
}

// assertOnlyMetricDropReason fails unless want is the one production drop
// reason counted, once.
func assertOnlyMetricDropReason(t *testing.T, objs *UsidObjects, want uint32) {
	t.Helper()
	for _, i := range DropReasonMetricIndices {
		got := sumPerCPU(t, objs.DropReasons, i)
		switch {
		case i == want && got != 1:
			t.Errorf("drop_reasons[%s] = %d, want 1", DropReasonNames[i], got)
		case i != want && got != 0:
			t.Errorf("drop_reasons[%s] = %d, want 0", DropReasonNames[i], got)
		}
	}
}

// TestUsidIngress_VIPXlat4LeavesOtherPacketsAlone: IPv4 packets that match no
// row (another destination, another port, another slot) and an IPv4 fragment
// that does not come from the gateway (no backend slot) are delivered as they
// arrived, as IPv4.
func TestUsidIngress_VIPXlat4LeavesOtherPacketsAlone(t *testing.T) {
	const moreFragments = 0x2000
	for _, tc := range []struct {
		name  string
		inner []byte
		slot  uint16
	}{
		{"OtherDestination", clientDatagram(ipProtoTCP, netip.MustParseAddr("203.0.113.11"), xlat4VIPPort, nil, 0, nil),
			xlat4Slot},
		{"OtherPort", clientDatagram(ipProtoTCP, xlat4VIP, xlat4VIPPort+1, nil, 0, nil), xlat4Slot},
		{"OtherSlot", clientDatagram(ipProtoTCP, xlat4VIP, xlat4VIPPort, nil, 0, nil), 0x1111},
		{"NoSlot", clientDatagram(ipProtoUDP, xlat4VIP, xlat4VIPPort, nil, 0, []byte("vpc")), 0},
		{"FragmentWithNoSlot", clientDatagram(ipProtoUDP, xlat4VIP, xlat4VIPPort, nil, moreFragments, []byte("vpc")), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, usid := vip4IngressFixture(t)
			usid.slot = tc.slot
			out := runIngressXlat4(t, objs, encapsulate4(usid.addr(t), tc.inner))
			if !bytes.Equal(out[ethHeaderLen:ethHeaderLen+len(tc.inner)], tc.inner) {
				t.Errorf("packet changed:\n in: % x\nout: % x", tc.inner, out[ethHeaderLen:])
			}
		})
	}
}

// TestUsidIngress_VIPXlat4IPv6PathsUnaffected: on the same backend socket, an
// IPv6 client's packet to the IPv6 VIP is still rewritten to the backend with
// its own source kept, and an IPv6 packet to the IPv4 VIP's IPv4-mapped
// address never takes the IPv4 VIP's row.
func TestUsidIngress_VIPXlat4IPv6PathsUnaffected(t *testing.T) {
	src := netip.MustParseAddr("2001:db8:ffff::1")
	for _, tc := range []struct {
		name    string
		dst     netip.Addr
		wantDst netip.Addr
	}{
		{"IPv6VIP", xlat4VIP6, xlat4Backend},
		{"MappedIPv4VIP", netip.AddrFrom16(xlat4VIP.As16()), netip.AddrFrom16(xlat4VIP.As16())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, usid := vip4IngressFixture(t)
			l4 := l4Header(ipProtoTCP, xlat4ClientPort, xlat4VIPPort, []byte("v6"))
			setL4Checksum(ipProtoTCP, src, tc.dst, l4)
			pkt := buildPacketWithV6Inner(usid.addr(t), ip6Datagram(ipProtoTCP, src, tc.dst, 0, 0, l4))

			got := parseIP6(t, runIngressXlat4(t, objs, pkt)[ethHeaderLen:])
			if got.dst != tc.wantDst || got.src != src || !got.l4Valid {
				t.Errorf("packet %s -> %s (checksum valid %v), want %s -> %s and valid",
					got.src, got.dst, got.l4Valid, src, tc.wantDst)
			}
		})
	}
}

// withTTL returns the IPv4 packet pkt with TTL ttl and its header checksum
// recomputed.
func withTTL(pkt []byte, ttl byte) []byte {
	out := bytes.Clone(pkt)
	ihl := int(out[0]&0x0F) * 4
	out[8] = ttl
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], ^fold(onesComplementSum(0, out[:ihl])))
	return out
}

// nativeVIPPort is the VIP port the IPv4-backend row in
// TestUsidIngress_VIPXlat4DropsUntranslatable is keyed on.
const nativeVIPPort = 8080

// TestUsidIngress_VIPXlat4TranslatedPacketSkipsIPv6Rewrites: a translated
// packet already carries the backend's real address, so neither the IPv6
// VIP lookup nor NPTv6 touches it, even where a row is keyed on that address
// and port or the VRF has NPTv6.
func TestUsidIngress_VIPXlat4TranslatedPacketSkipsIPv6Rewrites(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setUp func(*testing.T, *UsidObjects, testUSID)
	}{
		{"IPv6VIPRowOnBackend", func(t *testing.T, objs *UsidObjects, usid testUSID) {
			putXlatRow(t, objs, usid.block, usid.argument, usid.slot, ipProtoTCP, usidVIPXlatDirIngress,
				xlat4Backend, xlat4BackendPort, netip.MustParseAddr("fd20:60::99"), 9999)
		}},
		{"NPTv6", func(t *testing.T, objs *UsidObjects, usid testUSID) {
			putNPTv6(t, objs, usid.block, usid.argument)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, usid := vip4IngressFixture(t)
			tc.setUp(t, objs, usid)
			in := clientDatagram(ipProtoTCP, xlat4VIP, xlat4VIPPort, nil, 0, []byte("once"))
			got := parseIP6(t, runIngressXlat4(t, objs, encapsulate4(usid.addr(t), in))[ethHeaderLen:])
			if got.dst != xlat4Backend || got.dport != xlat4BackendPort || !got.l4Valid {
				t.Errorf("translated packet left for %s:%d (checksum valid %v), want %s:%d and valid",
					got.dst, got.dport, got.l4Valid, xlat4Backend, xlat4BackendPort)
			}
		})
	}
}

// TestUsidIngress_VIPXlat4TruncatedPacketUntouched: an IPv4 packet whose total
// length claims more bytes than arrived is not translated, since its IPv6
// payload length would claim bytes that are not there.
func TestUsidIngress_VIPXlat4TruncatedPacketUntouched(t *testing.T) {
	objs, usid := vip4IngressFixture(t)
	in := clientDatagram(ipProtoUDP, xlat4VIP, xlat4VIPPort, nil, 0, []byte("short"))
	binary.BigEndian.PutUint16(in[2:4], uint16(len(in)+64))
	binary.BigEndian.PutUint16(in[10:12], 0)
	binary.BigEndian.PutUint16(in[10:12], ^fold(onesComplementSum(0, in[:20])))

	out := runIngressXlat4(t, objs, encapsulate4(usid.addr(t), in))
	if !bytes.Equal(out[ethHeaderLen:ethHeaderLen+len(in)], in) {
		t.Errorf("truncated packet changed:\n in: % x\nout: % x", in, out[ethHeaderLen:])
	}
}

// buildPacketWithV6Inner wraps an IPv6 packet in an Ethernet and outer IPv6
// header toward outerDst with Next Header 41.
func buildPacketWithV6Inner(outerDst netip.Addr, inner []byte) []byte {
	pkt := encapsulate4(outerDst, inner)
	pkt[ethHeaderLen+6] = 41
	return pkt
}

// The uplink MACs the egress fixture publishes.
var (
	xlat4UplinkDMAC = [6]byte{0x02, 0, 0, 0, 0, 0xD1}
	xlat4UplinkSMAC = [6]byte{0x02, 0, 0, 0, 0, 0x51}
)

// xlat4ShardSID is the egress shard the egress fixture's NAT64 route
// encapsulates toward.
var xlat4ShardSID = netip.MustParseAddr("2001:db8:ff01:2002:e705::")

// vip4EgressFixture registers a tenant attachment whose backend socket
// xlat4Backend:xlat4BackendPort serves both VIPs, for TCP and UDP: the IPv4
// VIP's translated egress row and the IPv6 VIP's egress row. It also
// configures the public uplink and a NAT64 route for 64:ff9b::/96 toward an
// egress shard.
func vip4EgressFixture(t *testing.T) *UsidObjects {
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
	if err := objs.EgressRouteTable.Put(
		egressRouteKey(tableID, egressRouteFamilyINET6, netip.MustParseAddr("64:ff9b::"), 96),
		UsidEgressRouteValue{
			Sid: xlat4ShardSID.As16(), LinkIfindex: 1,
			Dmac: [6]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, Smac: [6]byte{0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB},
		}); err != nil {
		t.Fatalf("populate egress_route_table: %v", err)
	}
	setUpNodeSIDBase(t, objs, netip.MustParseAddr("2001:db8:ff01:1:e000::"), argument)
	for _, proto := range []uint8{ipProtoTCP, ipProtoUDP} {
		putXlatRow(t, objs, block, argument, 0, proto, usidVIPXlatDirEgressXlat,
			xlat4Backend, xlat4BackendPort, xlat4VIP, xlat4VIPPort)
		putXlatRow(t, objs, block, argument, 0, proto, usidVIPXlatDirEgress,
			xlat4Backend, xlat4BackendPort, xlat4VIP6, xlat4VIPPort)
	}
	return objs
}

// backendReply builds the backend's checksummed IPv6 reply from src:sport to
// dst:xlat4ClientPort, with traffic class xlat4TOS and a flow label.
func backendReply(proto byte, src netip.Addr, sport uint16, dst netip.Addr, payload []byte) []byte {
	l4 := l4Header(proto, sport, xlat4ClientPort, payload)
	setL4Checksum(proto, src, dst, l4)
	return withEth(0x86DD, ip6Datagram(proto, src, dst, xlat4TOS, 0xBEEF, l4))
}

// runEgressRedirect sends pkt through usid_egress and returns the frame it
// redirects. Any other verdict fails the test.
func runEgressRedirect(t *testing.T, objs *UsidObjects, pkt []byte) []byte {
	t.Helper()
	ret, out, err := objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActRedirect {
		t.Fatalf("verdict = %d, want TC_ACT_REDIRECT (%d)", ret, tcActRedirect)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonVIPXlatFailed); got != 0 {
		t.Fatalf("drop_reasons[vip_xlat_failed] = %d, want 0", got)
	}
	return out
}

// TestUsidEgress_VIPXlat4TranslatesReplyToIPv4: the backend's TCP or UDP reply
// to a client's 64:ff9b:: address leaves as IPv4 from the VIP's address and
// port to the client's own address, unencapsulated, out the public uplink, past
// the VRF's NAT64 route. Its header has no options, the hop limit less one as
// TTL, the traffic class as TOS, ID 0 and Don't Fragment, and both checksums
// are valid.
func TestUsidEgress_VIPXlat4TranslatesReplyToIPv4(t *testing.T) {
	payload := []byte("hello, client")
	for _, proto := range []byte{ipProtoTCP, ipProtoUDP} {
		t.Run(map[byte]string{ipProtoTCP: "TCP", ipProtoUDP: "UDP"}[proto], func(t *testing.T) {
			objs := vip4EgressFixture(t)
			pkt := backendReply(proto, xlat4Backend, xlat4BackendPort, xlat4ClientMapped, payload)

			out := runEgressRedirect(t, objs, pkt)
			if len(out) != len(pkt)-20 {
				t.Fatalf("output length = %d, want %d: one IPv4 header for the IPv6 one, and no encapsulation",
					len(out), len(pkt)-20)
			}
			if !bytes.Equal(out[0:6], xlat4UplinkDMAC[:]) || !bytes.Equal(out[6:12], xlat4UplinkSMAC[:]) {
				t.Errorf("MACs = % x / % x, want the public uplink's", out[0:6], out[6:12])
			}
			if got := binary.BigEndian.Uint16(out[12:14]); got != 0x0800 {
				t.Errorf("EtherType = %#04x, want 0x0800", got)
			}
			got := parseIP4(t, out[ethHeaderLen:])
			if got.src != xlat4VIP || got.sport != xlat4VIPPort {
				t.Errorf("source = %s:%d, want %s:%d", got.src, got.sport, xlat4VIP, xlat4VIPPort)
			}
			if got.dst != xlat4Client || got.dport != xlat4ClientPort {
				t.Errorf("destination = %s:%d, want the client's %s:%d", got.dst, got.dport, xlat4Client, xlat4ClientPort)
			}
			if got.ihl != 20 || got.ttl != xlat4TTL-1 || got.tos != xlat4TOS || got.id != 0 || got.fragOff != 0x4000 {
				t.Errorf("IHL %d, TTL %d, TOS %#02x, ID %#x, flags/offset %#04x; want 20, %d, %#02x, 0, 0x4000",
					got.ihl, got.ttl, got.tos, got.id, got.fragOff, xlat4TTL-1, xlat4TOS)
			}
			if !got.hdrValid || !got.l4Valid {
				t.Errorf("header checksum valid %v, L4 checksum %#04x valid %v; want both valid",
					got.hdrValid, got.l4csum, got.l4Valid)
			}
			if !bytes.Equal(got.payload, payload) {
				t.Errorf("payload = %q, want %q", got.payload, payload)
			}
		})
	}
}

// TestUsidEgress_VIPXlat4HopLimitExceeded: a reply whose hop limit
// translation would exhaust is dropped and counted, not sent.
func TestUsidEgress_VIPXlat4HopLimitExceeded(t *testing.T) {
	for _, hop := range []byte{0, 1} {
		objs := vip4EgressFixture(t)
		pkt := backendReply(ipProtoTCP, xlat4Backend, xlat4BackendPort, xlat4ClientMapped, []byte("hop"))
		pkt[ethHeaderLen+7] = hop
		ret, _, err := objs.UsidEgress.Test(pkt)
		if err != nil {
			t.Fatalf("program test-run: %v", err)
		}
		if ret != tcActShot {
			t.Errorf("hop limit %d: verdict = %d, want TC_ACT_SHOT (%d)", hop, ret, tcActShot)
		}
		assertOnlyMetricDropReason(t, objs, DropReasonVIPTTLExceeded)
	}
}

// TestUsidEgress_VIPXlat4UDPNoChecksumStaysZero: an IPv6 UDP reply whose
// checksum field is zero leaves as IPv4 UDP with no checksum, rather than one
// made wrong by an update.
func TestUsidEgress_VIPXlat4UDPNoChecksumStaysZero(t *testing.T) {
	objs := vip4EgressFixture(t)
	l4 := l4Header(ipProtoUDP, xlat4BackendPort, xlat4ClientPort, []byte("no checksum"))
	pkt := withEth(0x86DD, ip6Datagram(ipProtoUDP, xlat4Backend, xlat4ClientMapped, 0, 0, l4))

	got := parseIP4(t, runEgressRedirect(t, objs, pkt)[ethHeaderLen:])
	if got.l4csum != 0 || got.src != xlat4VIP || !got.hdrValid {
		t.Errorf("UDP checksum %#04x, source %s, header valid %v; want 0, %s and valid",
			got.l4csum, got.src, got.hdrValid, xlat4VIP)
	}
}

// TestUsidEgress_VIPXlat4ClampsSYNACK: the backend's SYN-ACK on an IPv4 VIP
// is clamped to the IPv4 limit, the family the client's segments reach the
// backend's node in, with the checksum still valid after both rewrites.
func TestUsidEgress_VIPXlat4ClampsSYNACK(t *testing.T) {
	objs := vip4EgressFixture(t)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	seg := tcpSegment(tcpFlagSYN|tcpFlagACK, linuxSYNOptions(1440), 0)
	binary.BigEndian.PutUint16(seg[0:2], xlat4BackendPort)
	binary.BigEndian.PutUint16(seg[2:4], xlat4ClientPort)
	setTCPChecksum(seg, xlat4Backend, xlat4ClientMapped)
	pkt := withEth(0x86DD, ip6Datagram(ipProtoTCP, xlat4Backend, xlat4ClientMapped, 0, 0, seg))

	l3 := runEgressRedirect(t, objs, pkt)[ethHeaderLen:]
	got := parseIP4(t, l3)
	if got.src != xlat4VIP || !got.hdrValid || !got.l4Valid {
		t.Errorf("source %s, header valid %v, TCP valid %v; want %s and both valid",
			got.src, got.hdrValid, got.l4Valid, xlat4VIP)
	}
	if mss, ok := mssOf(l3[20:]); !ok || mss != testMSSLimitV4 {
		t.Errorf("MSS = %d (present %v), want %d", mss, ok, testMSSLimitV4)
	}
}

// TestUsidEgress_VIPXlat4NoRowIsNAT64Egress: a reply to 64:ff9b::/96 that no
// translated row matches, from another port or another workload, is ordinary
// NAT64 traffic: it is encapsulated unchanged toward the egress shard.
func TestUsidEgress_VIPXlat4NoRowIsNAT64Egress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		src   netip.Addr
		sport uint16
	}{
		{"OtherPort", xlat4Backend, xlat4BackendPort + 1},
		{"NotTheBackend", netip.MustParseAddr("fd20:60::6"), xlat4BackendPort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := vip4EgressFixture(t)
			pkt := backendReply(ipProtoTCP, tc.src, tc.sport, xlat4ClientMapped, []byte("out"))

			out := runEgressRedirect(t, objs, pkt)
			if len(out) != len(pkt)+ip6HeaderLen {
				t.Fatalf("output length = %d, want %d: encapsulated toward the shard", len(out), len(pkt)+ip6HeaderLen)
			}
			if got, _ := netip.AddrFromSlice(out[ethHeaderLen+24 : ethHeaderLen+40]); got != xlat4ShardSID {
				t.Errorf("outer destination = %s, want the shard %s", got, xlat4ShardSID)
			}
			if !bytes.Equal(out[ethHeaderLen+ip6HeaderLen:], pkt[ethHeaderLen:]) {
				t.Errorf("inner packet changed:\n in: % x\nout: % x", pkt[ethHeaderLen:], out[ethHeaderLen+ip6HeaderLen:])
			}
		})
	}
}

// TestUsidEgress_VIPXlat4IPv6VIPReplyUnaffected: the same backend socket's
// reply to an IPv6 client still leaves as IPv6 from the IPv6 VIP, out the
// public uplink.
func TestUsidEgress_VIPXlat4IPv6VIPReplyUnaffected(t *testing.T) {
	objs := vip4EgressFixture(t)
	client := netip.MustParseAddr("2001:db8:ffff::1")
	pkt := backendReply(ipProtoUDP, xlat4Backend, xlat4BackendPort, client, []byte("v6"))

	out := runEgressRedirect(t, objs, pkt)
	if len(out) != len(pkt) || !bytes.Equal(out[0:6], xlat4UplinkDMAC[:]) {
		t.Fatalf("output length %d, destination MAC % x; want %d and the public uplink's", len(out), out[0:6], len(pkt))
	}
	got := parseIP6(t, out[ethHeaderLen:])
	if got.src != xlat4VIP6 || got.sport != xlat4VIPPort || got.dst != client || !got.l4Valid {
		t.Errorf("reply %s:%d -> %s (checksum valid %v), want %s:%d -> %s and valid",
			got.src, got.sport, got.dst, got.l4Valid, xlat4VIP6, xlat4VIPPort, client)
	}
}

// TestUsidEgress_VIPXlat4LeavesOtherPacketsAlone: an IPv6 packet from an
// IPv4-mapped source, even with a row keyed on it, and a reply carrying an
// extension header are not translated.
func TestUsidEgress_VIPXlat4LeavesOtherPacketsAlone(t *testing.T) {
	const ipProtoFragment = 44
	mapped := netip.AddrFrom16(netip.MustParseAddr("10.60.0.5").As16())
	fragment := func() []byte {
		l4 := l4Header(ipProtoUDP, xlat4BackendPort, xlat4ClientPort, []byte("a"))
		setL4Checksum(ipProtoUDP, xlat4Backend, xlat4ClientMapped, l4)
		ext := make([]byte, 0, 8+len(l4))
		ext = append(ext, ipProtoUDP, 0, 0, 1, 0, 0, 0, 1) // first fragment, more to follow
		return withEth(0x86DD, ip6Datagram(ipProtoFragment, xlat4Backend, xlat4ClientMapped, 0, 0, append(ext, l4...)))
	}
	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"MappedSource", backendReply(ipProtoTCP, mapped, xlat4BackendPort, xlat4ClientMapped, nil)},
		{"Fragment", fragment()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := vip4EgressFixture(t)
			putXlatRow(t, objs, 0xFEEDFA, 0x705, 0, ipProtoTCP, usidVIPXlatDirEgressXlat,
				mapped, xlat4BackendPort, xlat4VIP, xlat4VIPPort)

			out := runEgressRedirect(t, objs, tc.pkt)
			if len(out) != len(tc.pkt)+ip6HeaderLen ||
				!bytes.Equal(out[ethHeaderLen+ip6HeaderLen:], tc.pkt[ethHeaderLen:]) {
				t.Errorf("packet translated or changed; want it encapsulated unchanged toward the shard:\n in: % x\nout: % x",
					tc.pkt, out)
			}
		})
	}
}
