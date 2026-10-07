// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// Tests for clamp_tcp_mss, through each of its three call sites: usid_egress
// before encapsulation, usid_egress's DSR reply redirect, and usid_ingress
// after decapsulation.
//
// Every test that expects a rewrite also checks the TCP checksum by a full
// independent recompute, since an MSS that is right with a checksum that is
// wrong is a dropped SYN.

const (
	testMSSLimitV4 = 1420
	testMSSLimitV6 = 1400
	tcpFlagSYN     = 0x02
	tcpFlagACK     = 0x10
	ipProtoTCP     = 6
	ipProtoUDP     = 17
)

var (
	tcpOptNOP      = []byte{1}
	tcpOptSACKPerm = []byte{4, 2}
	tcpOptWScale   = []byte{3, 3, 7}
	tcpOptTS       = []byte{8, 10, 0, 0, 0, 1, 0, 0, 0, 0}
)

func tcpOptMSS(v uint16) []byte { return []byte{2, 4, byte(v >> 8), byte(v)} }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// linuxSYNOptions is the option list a Linux SYN carries, in Linux's order.
func linuxSYNOptions(mss uint16) []byte {
	return concat(tcpOptMSS(mss), tcpOptSACKPerm, tcpOptTS, tcpOptNOP, tcpOptWScale)
}

// tcpSegment builds a TCP header with options, padded to a 4-byte boundary
// with EOL, and no payload: a SYN carries none. The checksum field is left
// zero.
// doffWords, when nonzero, overrides the data offset the header claims, for
// malformed-header cases.
func tcpSegment(flags byte, options []byte, doffWords int) []byte {
	opts := append([]byte{}, options...)
	for len(opts)%4 != 0 {
		opts = append(opts, 0) // EOL padding
	}
	seg := make([]byte, 20, 20+len(opts))
	binary.BigEndian.PutUint16(seg[0:2], 40000)
	binary.BigEndian.PutUint16(seg[2:4], 80)
	binary.BigEndian.PutUint32(seg[4:8], 1)
	doff := (20 + len(opts)) / 4
	if doffWords != 0 {
		doff = doffWords
	}
	seg[12] = byte(doff << 4)
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	return append(seg, opts...)
}

func onesComplementSum(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return uint16(sum)
}

// pseudoHeaderSum is the TCP pseudo-header sum for src and dst, either both
// IPv4 or both IPv6.
func pseudoHeaderSum(src, dst netip.Addr, segLen int) uint32 {
	var sum uint32
	sum = onesComplementSum(sum, src.AsSlice())
	sum = onesComplementSum(sum, dst.AsSlice())
	return sum + ipProtoTCP + uint32(segLen)
}

// setTCPChecksum fills in seg's checksum for src and dst.
func setTCPChecksum(seg []byte, src, dst netip.Addr) {
	seg[16], seg[17] = 0, 0
	csum := ^fold(onesComplementSum(pseudoHeaderSum(src, dst, len(seg)), seg))
	binary.BigEndian.PutUint16(seg[16:18], csum)
}

// tcpChecksumValid reports whether seg's checksum is correct for src and dst.
func tcpChecksumValid(seg []byte, src, dst netip.Addr) bool {
	return fold(onesComplementSum(pseudoHeaderSum(src, dst, len(seg)), seg)) == 0xFFFF
}

// ip6TCP returns an IPv6 header carrying seg, with no Ethernet header.
// nexthdr is usually TCP; a test of extension-header handling passes another.
func ip6TCP(src, dst netip.Addr, nexthdr byte, seg []byte) []byte {
	hdr := make([]byte, 40, 40+len(seg))
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(seg)))
	hdr[6] = nexthdr
	hdr[7] = 64
	copy(hdr[8:24], src.AsSlice())
	copy(hdr[24:40], dst.AsSlice())
	return append(hdr, seg...)
}

// ip4TCP returns an IPv4 header carrying seg, with ipOptions (a multiple of 4
// bytes) and fragOff as given, and a correct header checksum.
func ip4TCP(src, dst netip.Addr, ipOptions []byte, fragOff uint16, seg []byte) []byte {
	ihl := 20 + len(ipOptions)
	hdr := make([]byte, 20, ihl)
	hdr[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(ihl+len(seg)))
	binary.BigEndian.PutUint16(hdr[6:8], fragOff)
	hdr[8] = 64
	hdr[9] = ipProtoTCP
	copy(hdr[12:16], src.AsSlice())
	copy(hdr[16:20], dst.AsSlice())
	hdr = append(hdr, ipOptions...)
	binary.BigEndian.PutUint16(hdr[10:12], ^fold(onesComplementSum(0, hdr)))
	return append(hdr, seg...)
}

func withEth(etherType uint16, l3 []byte) []byte {
	pkt := make([]byte, 0, ethHeaderLen+len(l3))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0, 0)
	binary.BigEndian.PutUint16(pkt[12:14], etherType)
	return append(pkt, l3...)
}

// mssOf walks seg's options in Go and returns its MSS, if it has one.
func mssOf(seg []byte) (uint16, bool) {
	end := int(seg[12]>>4) * 4
	for off := 20; off < end && off < len(seg); {
		switch seg[off] {
		case 0:
			return 0, false
		case 1:
			off++
			continue
		}
		if off+1 >= len(seg) || seg[off+1] < 2 {
			return 0, false
		}
		if seg[off] == 2 && seg[off+1] == 4 && off+4 <= len(seg) {
			return binary.BigEndian.Uint16(seg[off+2 : off+4]), true
		}
		off += int(seg[off+1])
	}
	return 0, false
}

func setMSSClamp(t *testing.T, objs *UsidObjects, v4, v6 uint16) {
	t.Helper()
	if err := objs.MssClampTable.Put(uint32(0), UsidMssClampValue{MssIpv4: v4, MssIpv6: v6}); err != nil {
		t.Fatalf("populate mss_clamp_table: %v", err)
	}
}

// assertMSSStats checks every mss_clamp_stats slot: those named in want hold
// that count, every other slot is zero.
func assertMSSStats(t *testing.T, objs *UsidObjects, want map[uint32]uint64) {
	t.Helper()
	for i := range MSSClampStatCount {
		if got := sumPerCPU(t, objs.MssClampStats, i); got != want[i] {
			t.Errorf("mss_clamp_stats[%s] = %d, want %d", MSSClampStatNames[i], got, want[i])
		}
	}
}

var (
	mssPodV6    = netip.MustParseAddr("fd20:70::1")
	mssRemoteV6 = netip.MustParseAddr("2001:db8:1:40::2")
	mssPodV4    = netip.MustParseAddr("172.21.1.5")
	mssRemoteV4 = netip.MustParseAddr("10.1.40.2")
)

// egressClampFixture registers one tenant attachment whose IPv4 and IPv6
// defaults encapsulate toward a shard, the path a pod's SYN to the internet
// takes, and returns the loaded objects.
func egressClampFixture(t *testing.T) *UsidObjects {
	t.Helper()
	requireRoot(t)
	objs := loadObjects(t)

	const tableID = 21
	const argument = 0x210
	setUpEgressRouteAttachment(t, objs, 0x123456, argument, tableID)
	sid := netip.MustParseAddr("2001:db8:ff01:2002:e210::")
	for _, k := range []UsidEgressRouteKey{
		egressRouteKey(tableID, egressRouteFamilyINET6, netip.IPv6Unspecified(), 0),
		egressRouteKey(tableID, egressRouteFamilyINET4, netip.IPv4Unspecified(), 0),
	} {
		if err := objs.EgressRouteTable.Put(k, UsidEgressRouteValue{
			Sid: sid.As16(), LinkIfindex: 1,
			Dmac: [6]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, Smac: [6]byte{0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB},
		}); err != nil {
			t.Fatalf("populate egress_route_table: %v", err)
		}
	}
	setUpNodeSIDBase(t, objs, netip.MustParseAddr("2001:db8:ff01:1:e000::"), argument)
	return objs
}

// runEgress runs usid_egress on pkt, requires it to encapsulate, and returns
// the tenant packet from inside the new outer header, starting at its IP
// header.
func runEgress(t *testing.T, objs *UsidObjects, pkt []byte) []byte {
	t.Helper()
	ret, out, err := objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActRedirect {
		t.Fatalf("verdict = %d, want TC_ACT_REDIRECT (%d): the SYN must still be encapsulated and sent", ret, tcActRedirect)
	}
	if want := len(pkt) + ip6HeaderLen; len(out) != want {
		t.Fatalf("output length = %d, want %d: the clamp must not change the packet's length", len(out), want)
	}
	return out[ethHeaderLen+ip6HeaderLen:]
}

func v6SYN(t *testing.T, flags byte, options []byte) []byte {
	t.Helper()
	seg := tcpSegment(flags, options, 0)
	setTCPChecksum(seg, mssPodV6, mssRemoteV6)
	return withEth(0x86DD, ip6TCP(mssPodV6, mssRemoteV6, ipProtoTCP, seg))
}

func v4SYN(t *testing.T, flags byte, options []byte) []byte {
	t.Helper()
	seg := tcpSegment(flags, options, 0)
	setTCPChecksum(seg, mssPodV4, mssRemoteV4)
	return withEth(0x0800, ip4TCP(mssPodV4, mssRemoteV4, nil, 0, seg))
}

// TestMSSClamp_EgressClampsIPv6SYN is the core case: a pod's SYN advertises
// the MSS its 1500-byte interface implies, 1440, and leaves clamped to 1400 so
// every reply segment fits once encapsulated.
func TestMSSClamp_EgressClampsIPv6SYN(t *testing.T) {
	objs := egressClampFixture(t)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	pkt := v6SYN(t, tcpFlagSYN, linuxSYNOptions(1440))
	inner := runEgress(t, objs, pkt)
	seg := inner[ip6HeaderLen:]

	if mss, ok := mssOf(seg); !ok || mss != testMSSLimitV6 {
		t.Errorf("MSS after clamp = %d (found %v), want %d", mss, ok, testMSSLimitV6)
	}
	if !tcpChecksumValid(seg, mssPodV6, mssRemoteV6) {
		t.Error("TCP checksum is invalid after the clamp: the receiver would drop this SYN")
	}
	assertMSSStats(t, objs, map[uint32]uint64{MSSClampStatClampedIPv6: 1})
}

// TestMSSClamp_EgressClampsIPv4SYN covers the IPv4 family, whose limit is 20
// bytes higher because its inner header is 20 bytes smaller, and checks the
// IPv4 header is untouched: the MSS is TCP payload, not IP header.
func TestMSSClamp_EgressClampsIPv4SYN(t *testing.T) {
	objs := egressClampFixture(t)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	pkt := v4SYN(t, tcpFlagSYN, linuxSYNOptions(1460))
	inner := runEgress(t, objs, pkt)

	if string(inner[:20]) != string(pkt[ethHeaderLen:ethHeaderLen+20]) {
		t.Errorf("IPv4 header changed by the clamp:\n want % x\n  got % x", pkt[ethHeaderLen:ethHeaderLen+20], inner[:20])
	}
	seg := inner[20:]
	if mss, ok := mssOf(seg); !ok || mss != testMSSLimitV4 {
		t.Errorf("MSS after clamp = %d (found %v), want %d", mss, ok, testMSSLimitV4)
	}
	if !tcpChecksumValid(seg, mssPodV4, mssRemoteV4) {
		t.Error("TCP checksum is invalid after the clamp")
	}
	assertMSSStats(t, objs, map[uint32]uint64{MSSClampStatClampedIPv4: 1})
}

// TestMSSClamp_EgressClampsSYNACK covers the other half of a handshake: a pod
// answering a connection from a remote pod. Its SYN-ACK is what sizes the
// remote side's segments.
func TestMSSClamp_EgressClampsSYNACK(t *testing.T) {
	objs := egressClampFixture(t)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	pkt := v6SYN(t, tcpFlagSYN|tcpFlagACK, linuxSYNOptions(1440))
	seg := runEgress(t, objs, pkt)[ip6HeaderLen:]
	if mss, _ := mssOf(seg); mss != testMSSLimitV6 {
		t.Errorf("SYN-ACK MSS after clamp = %d, want %d", mss, testMSSLimitV6)
	}
	if !tcpChecksumValid(seg, mssPodV6, mssRemoteV6) {
		t.Error("TCP checksum is invalid after the clamp")
	}
}

// TestMSSClamp_FindsMSSAnywhereInOptions covers MSS positions a stack other
// than Linux's might use: after NOP padding, after timestamps, and last.
func TestMSSClamp_FindsMSSAnywhereInOptions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []byte
	}{
		{"after two NOPs", concat(tcpOptNOP, tcpOptNOP, tcpOptMSS(1440))},
		{"after timestamps", concat(tcpOptNOP, tcpOptNOP, tcpOptTS, tcpOptMSS(1440))},
		{"last of five", concat(tcpOptSACKPerm, tcpOptTS, tcpOptNOP, tcpOptWScale, tcpOptMSS(1440))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := egressClampFixture(t)
			setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

			pkt := v6SYN(t, tcpFlagSYN, tc.options)
			seg := runEgress(t, objs, pkt)[ip6HeaderLen:]
			if mss, _ := mssOf(seg); mss != testMSSLimitV6 {
				t.Errorf("MSS after clamp = %d, want %d", mss, testMSSLimitV6)
			}
			if !tcpChecksumValid(seg, mssPodV6, mssRemoteV6) {
				t.Error("TCP checksum is invalid after the clamp")
			}
		})
	}
}

// TestMSSClamp_IPv4HeaderWithOptions checks the TCP header is found past IPv4
// options, through IHL, rather than assumed at a fixed 20-byte offset.
func TestMSSClamp_IPv4HeaderWithOptions(t *testing.T) {
	objs := egressClampFixture(t)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	seg := tcpSegment(tcpFlagSYN, linuxSYNOptions(1460), 0)
	setTCPChecksum(seg, mssPodV4, mssRemoteV4)
	ipOpts := []byte{1, 1, 1, 0} // NOP, NOP, NOP, EOL: one 4-byte word, IHL 6
	pkt := withEth(0x0800, ip4TCP(mssPodV4, mssRemoteV4, ipOpts, 0, seg))

	got := runEgress(t, objs, pkt)[24:]
	if mss, _ := mssOf(got); mss != testMSSLimitV4 {
		t.Errorf("MSS after clamp = %d, want %d", mss, testMSSLimitV4)
	}
	if !tcpChecksumValid(got, mssPodV4, mssRemoteV4) {
		t.Error("TCP checksum is invalid after the clamp")
	}
}

// TestMSSClamp_LeavesPacketUntouched covers every case where the clamp must
// not change a byte, and which stat, if any, each one counts. Each is a
// packet the clamp either has no business with or cannot safely parse.
func TestMSSClamp_LeavesPacketUntouched(t *testing.T) {
	v6 := func(flags byte, options []byte, doff int) []byte {
		seg := tcpSegment(flags, options, doff)
		setTCPChecksum(seg, mssPodV6, mssRemoteV6)
		return withEth(0x86DD, ip6TCP(mssPodV6, mssRemoteV6, ipProtoTCP, seg))
	}
	// A SYN-shaped body for the cases that are not a plain IPv6 TCP SYN.
	synBody := tcpSegment(tcpFlagSYN, linuxSYNOptions(1440), 0)
	sixteenNOPs := make([]byte, 16)
	for i := range sixteenNOPs {
		sixteenNOPs[i] = 1
	}

	for _, tc := range []struct {
		name  string
		pkt   []byte
		stats map[uint32]uint64
	}{
		{"MSS already below the limit", v6(tcpFlagSYN, linuxSYNOptions(1300), 0),
			map[uint32]uint64{MSSClampStatWithinLimit: 1}},
		{"MSS exactly at the limit", v6(tcpFlagSYN, linuxSYNOptions(testMSSLimitV6), 0),
			map[uint32]uint64{MSSClampStatWithinLimit: 1}},
		{"not a SYN, though an MSS option is present", v6(tcpFlagACK, linuxSYNOptions(1440), 0), nil},
		{"SYN with no MSS option", v6(tcpFlagSYN, concat(tcpOptSACKPerm, tcpOptTS), 0),
			map[uint32]uint64{MSSClampStatNoMSSOption: 1}},
		{"SYN with no options at all", v6(tcpFlagSYN, nil, 0),
			map[uint32]uint64{MSSClampStatNoMSSOption: 1}},
		{"MSS after an EOL", v6(tcpFlagSYN, concat([]byte{0, 0, 0, 0}, tcpOptMSS(1440)), 0),
			map[uint32]uint64{MSSClampStatNoMSSOption: 1}},
		{"option length zero", v6(tcpFlagSYN, concat([]byte{8, 0}, tcpOptMSS(1440)), 0),
			map[uint32]uint64{MSSClampStatMalformedOptions: 1}},
		{"option length one", v6(tcpFlagSYN, concat([]byte{8, 1}, tcpOptMSS(1440)), 0),
			map[uint32]uint64{MSSClampStatMalformedOptions: 1}},
		{"option running past the header", v6(tcpFlagSYN, concat(tcpOptSACKPerm, []byte{8, 40}), 0),
			map[uint32]uint64{MSSClampStatMalformedOptions: 1}},
		{"MSS option of the wrong length", v6(tcpFlagSYN, []byte{2, 3, 0x05, 0, 0, 0, 0, 0}, 0),
			map[uint32]uint64{MSSClampStatMalformedOptions: 1}},
		{"data offset below the fixed header", v6(tcpFlagSYN, linuxSYNOptions(1440), 4),
			map[uint32]uint64{MSSClampStatMalformedOptions: 1}},
		{"data offset past the end of the packet", v6(tcpFlagSYN, tcpOptMSS(1440), 15),
			map[uint32]uint64{MSSClampStatMalformedOptions: 1}},
		{"MSS beyond the walk limit", v6(tcpFlagSYN, concat(sixteenNOPs, tcpOptMSS(1440)), 0),
			map[uint32]uint64{MSSClampStatWalkLimit: 1}},
		{"UDP", withEth(0x86DD, ip6TCP(mssPodV6, mssRemoteV6, ipProtoUDP, synBody)), nil},
		{"IPv6 hop-by-hop extension header", withEth(0x86DD, ip6TCP(mssPodV6, mssRemoteV6, 0, synBody)),
			map[uint32]uint64{MSSClampStatSkippedExtHdr: 1}},
		// Fragment offset 16 (in 8-byte units): this fragment carries no TCP header.
		{"IPv4 non-first fragment", withEth(0x0800, ip4TCP(mssPodV4, mssRemoteV4, nil, 0x0010, synBody)), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := egressClampFixture(t)
			setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

			got := runEgress(t, objs, tc.pkt)
			if want := tc.pkt[ethHeaderLen:]; string(got) != string(want) {
				t.Errorf("tenant packet changed:\n want % x\n  got % x", want, got)
			}
			assertMSSStats(t, objs, tc.stats)
		})
	}
}

// TestMSSClamp_OffWhenUnconfigured is the rollout guarantee: until
// galactic-cni writes mss_clamp_table, the datapath behaves exactly as it did
// before the clamp existed. An array map's zero value is that state.
func TestMSSClamp_OffWhenUnconfigured(t *testing.T) {
	objs := egressClampFixture(t)

	pkt := v6SYN(t, tcpFlagSYN, linuxSYNOptions(1440))
	if got := runEgress(t, objs, pkt); string(got) != string(pkt[ethHeaderLen:]) {
		t.Error("SYN changed with mss_clamp_table never written, want it untouched")
	}
	assertMSSStats(t, objs, nil)
}

// TestMSSClamp_PerFamilyLimits checks each family reads its own limit: a zero
// limit turns off that family alone, and the other still clamps.
func TestMSSClamp_PerFamilyLimits(t *testing.T) {
	for _, tc := range []struct {
		name         string
		v4, v6       uint16
		clampedPkt   func(*testing.T, byte, []byte) []byte
		clampedMSS   uint16
		clampedOff   int // where the clamped family's TCP header starts
		untouchedPkt func(*testing.T, byte, []byte) []byte
		stat         uint32
	}{
		{"IPv6 off, IPv4 on", testMSSLimitV4, 0, v4SYN, testMSSLimitV4, 20, v6SYN, MSSClampStatClampedIPv4},
		{"IPv4 off, IPv6 on", 0, testMSSLimitV6, v6SYN, testMSSLimitV6, 40, v4SYN, MSSClampStatClampedIPv6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := egressClampFixture(t)
			setMSSClamp(t, objs, tc.v4, tc.v6)

			off := tc.untouchedPkt(t, tcpFlagSYN, linuxSYNOptions(1460))
			if got := runEgress(t, objs, off); string(got) != string(off[ethHeaderLen:]) {
				t.Error("SYN of the family whose limit is zero changed, want it untouched")
			}
			on := tc.clampedPkt(t, tcpFlagSYN, linuxSYNOptions(1460))
			if mss, _ := mssOf(runEgress(t, objs, on)[tc.clampedOff:]); mss != tc.clampedMSS {
				t.Errorf("MSS = %d, want %d: the other family's limit must apply on its own", mss, tc.clampedMSS)
			}
			assertMSSStats(t, objs, map[uint32]uint64{tc.stat: 1})
		})
	}
}

// TestMSSClamp_Idempotent runs an already-clamped SYN through again, as the
// receiving node's usid_ingress does to one this node's usid_egress clamped.
func TestMSSClamp_Idempotent(t *testing.T) {
	objs := egressClampFixture(t)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	pkt := v6SYN(t, tcpFlagSYN, linuxSYNOptions(1440))
	once := runEgress(t, objs, pkt)
	again := runEgress(t, objs, withEth(0x86DD, once))
	if string(again) != string(once) {
		t.Errorf("second pass changed an already-clamped SYN:\n first % x\nsecond % x", once, again)
	}
	assertMSSStats(t, objs, map[uint32]uint64{MSSClampStatClampedIPv6: 1, MSSClampStatWithinLimit: 1})
}

// TestMSSClamp_SameNodeTrafficKeepsFullMSS checks the clamp applies only to
// traffic that crosses the fabric. A destination this node delivers to
// directly matches a pass-through entry, defers to the kernel, and is never
// encapsulated, so its SYN keeps the full MSS.
func TestMSSClamp_SameNodeTrafficKeepsFullMSS(t *testing.T) {
	objs := egressClampFixture(t)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	local := netip.MustParseAddr("fd20:70::2")
	if err := objs.EgressRouteTable.Put(egressRouteKey(21, egressRouteFamilyINET6, local, 128),
		UsidEgressRouteValue{}); err != nil {
		t.Fatalf("populate pass-through entry: %v", err)
	}
	seg := tcpSegment(tcpFlagSYN, linuxSYNOptions(1440), 0)
	setTCPChecksum(seg, mssPodV6, local)
	pkt := withEth(0x86DD, ip6TCP(mssPodV6, local, ipProtoTCP, seg))

	ret, out, err := objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActUnspec {
		t.Fatalf("verdict = %d, want TC_ACT_UNSPEC: a same-node destination defers to the kernel", ret)
	}
	if string(out) != string(pkt) {
		t.Error("same-node SYN changed, want it untouched with its full MSS")
	}
	assertMSSStats(t, objs, nil)
}

// TestMSSClamp_DSRReplyClamped covers the gateway path: a DSR backend's
// SYN-ACK leaves through the public uplink with its source rewritten to the
// VIP, unencapsulated. The client's segments reach the backend encapsulated
// by the gateway, so this SYN-ACK is the one that has to carry the clamp.
func TestMSSClamp_DSRReplyClamped(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

	block, argument := uint64(0xFEEDFA), uint16(0x500)
	setUpEgressRouteAttachment(t, objs, block, argument, 13)

	backendReal := netip.MustParseAddr("fd20:60:ff03::100:0")
	vip := netip.MustParseAddr("2001:db8:6060::1")
	client := netip.MustParseAddr("2001:db8:0:13::1")
	if err := objs.VipXlatTable.Put(UsidVipXlatKey{
		Block: block, Argument: argument, Proto: ipProtoTCP, Direction: usidVIPXlatDirEgress, Port: bswap16(80),
		Addr: backendReal.As16(),
	}, UsidVipXlatValue{Addr: vip.As16(), Port: bswap16(80)}); err != nil {
		t.Fatalf("populate vip_xlat_table: %v", err)
	}
	if err := objs.PublicUplinkTable.Put(uint32(0), UsidPublicUplinkValue{LinkIfindex: 1}); err != nil {
		t.Fatalf("populate public_uplink_table: %v", err)
	}

	seg := tcpSegment(tcpFlagSYN|tcpFlagACK, linuxSYNOptions(1440), 0)
	binary.BigEndian.PutUint16(seg[0:2], 80)
	binary.BigEndian.PutUint16(seg[2:4], 43210)
	setTCPChecksum(seg, backendReal, client)
	pkt := withEth(0x86DD, ip6TCP(backendReal, client, ipProtoTCP, seg))

	ret, out, err := objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActRedirect {
		t.Fatalf("verdict = %d, want TC_ACT_REDIRECT to the public uplink", ret)
	}
	got := out[ethHeaderLen+ip6HeaderLen:]
	if mss, _ := mssOf(got); mss != testMSSLimitV6 {
		t.Errorf("DSR SYN-ACK MSS = %d, want %d", mss, testMSSLimitV6)
	}
	// Valid against the VIP, the source the client sees, which means the clamp
	// and the VIP rewrite's checksum updates composed correctly.
	if !tcpChecksumValid(got, vip, client) {
		t.Error("TCP checksum is invalid after the VIP rewrite and the clamp together")
	}
	assertMSSStats(t, objs, map[uint32]uint64{MSSClampStatClampedIPv6: 1})
}

// ingressClampFixture registers this node as the decapsulation point for one
// tenant VRF and returns the objects and the uSID a peer encapsulates toward.
func ingressClampFixture(t *testing.T) (*UsidObjects, netip.Addr) {
	t.Helper()
	requireRoot(t)
	objs := loadObjects(t)
	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x321}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: 0x2C2C2C}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
	return objs, usid.addr(t)
}

// runIngress runs usid_ingress on an encapsulated packet and returns the
// decapsulated tenant packet, starting at its IP header. The test table ID
// resolves to no real route, so the FIB lookup after the clamp fails and the
// verdict is a drop, but the output still shows every rewrite made before it.
func runIngress(t *testing.T, objs *UsidObjects, pkt []byte) []byte {
	t.Helper()
	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("verdict = %d, want TC_ACT_SHOT from the FIB lookup", ret)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed); got != 1 {
		t.Fatalf("drop_reasons[fib_lookup_failed] = %d, want 1: the packet must have reached the lookup after the clamp", got)
	}
	return out[ethHeaderLen:]
}

// TestMSSClamp_IngressClampsDecapsulatedSYNACK is the NAT case: the remote
// server's SYN-ACK comes back through an egress shard, which does not clamp,
// so this node's decapsulation is its one chance to be clamped before the pod
// sizes its own segments from it.
func TestMSSClamp_IngressClampsDecapsulatedSYNACK(t *testing.T) {
	for _, tc := range []struct {
		name       string
		nexthdr    byte
		src, dst   netip.Addr
		mss, limit uint16
		l3         func(seg []byte) []byte
		ipHdrLen   int
		stat       uint32
	}{
		{"IPv6 tenant", 41, mssRemoteV6, mssPodV6, 1440, testMSSLimitV6,
			func(seg []byte) []byte { return ip6TCP(mssRemoteV6, mssPodV6, ipProtoTCP, seg) }, 40, MSSClampStatClampedIPv6},
		{"IPv4 tenant", 4, mssRemoteV4, mssPodV4, 1460, testMSSLimitV4,
			func(seg []byte) []byte { return ip4TCP(mssRemoteV4, mssPodV4, nil, 0, seg) }, 20, MSSClampStatClampedIPv4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, usidAddr := ingressClampFixture(t)
			setMSSClamp(t, objs, testMSSLimitV4, testMSSLimitV6)

			seg := tcpSegment(tcpFlagSYN|tcpFlagACK, linuxSYNOptions(tc.mss), 0)
			setTCPChecksum(seg, tc.src, tc.dst)
			inner := tc.l3(seg)
			outer := ip6TCP(netip.MustParseAddr("2001:db8:ff01:2002:e321::"), usidAddr, tc.nexthdr, inner)
			outer[6] = tc.nexthdr
			got := runIngress(t, objs, withEth(0x86DD, outer))

			gotSeg := got[tc.ipHdrLen:]
			if mss, _ := mssOf(gotSeg); mss != tc.limit {
				t.Errorf("MSS after decap and clamp = %d, want %d", mss, tc.limit)
			}
			if !tcpChecksumValid(gotSeg, tc.src, tc.dst) {
				t.Error("TCP checksum is invalid after the clamp")
			}
			assertMSSStats(t, objs, map[uint32]uint64{tc.stat: 1})
		})
	}
}
