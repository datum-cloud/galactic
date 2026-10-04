// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// Tests for send_too_big, through usid_egress: a tenant packet too big to
// cross the fabric once encapsulated gets an ICMPv6 Packet Too Big or an
// ICMPv4 Fragmentation Needed back instead of being dropped by the uplink with
// no error (#641).
//
// Every error is checked byte for byte against an independent Go recompute of
// its checksums, and against a Go model of the kernel finishing an offloaded
// checksum (finishPartialChecksum), since that is what the error's layout is
// built to survive.

const (
	// testEncapMTU is the limit at a 1500-byte fabric.
	testEncapMTU = 1460

	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
	ipv4FlagDF    = 0x4000

	pmtuMsgLen = 80
)

var (
	pmtuGW6 = netip.MustParseAddr("fd20:70::fe")
	pmtuGW4 = netip.MustParseAddr("172.21.1.1")
)

// pmtuFixture is egressClampFixture plus what the check needs: the limit, and
// the attachment's gateways.
func pmtuFixture(t *testing.T) *UsidObjects {
	t.Helper()
	objs := egressClampFixture(t)
	setEncapMTU(t, objs, testEncapMTU)
	if err := objs.TenantGwTable.Put(uint32(1), UsidTenantGwValue{Gw6: pmtuGW6.As16(), Gw4: pmtuGW4.As4()}); err != nil {
		t.Fatalf("populate tenant_gw_table: %v", err)
	}
	return objs
}

func setEncapMTU(t *testing.T, objs *UsidObjects, limit uint32) {
	t.Helper()
	if err := objs.EncapMtuTable.Put(uint32(0), limit); err != nil {
		t.Fatalf("populate encap_mtu_table: %v", err)
	}
}

// assertPMTUStats checks every pmtu_stats slot: those named in want hold that
// count, every other slot is zero.
func assertPMTUStats(t *testing.T, objs *UsidObjects, want map[uint32]uint64) {
	t.Helper()
	for i := range PMTUStatCount {
		if got := sumPerCPU(t, objs.PmtuStats, i); got != want[i] {
			t.Errorf("pmtu_stats[%s] = %d, want %d", PMTUStatNames[i], got, want[i])
		}
	}
}

// l4Datagram returns a transport header for proto followed by payload bytes,
// with the checksum left zero. Only the bytes matter here, not their meaning.
func l4Datagram(proto byte, payloadLen int) []byte {
	hdrLen := 8
	if proto == ipProtoTCP {
		hdrLen = 20
	}
	seg := make([]byte, hdrLen+payloadLen)
	binary.BigEndian.PutUint16(seg[0:2], 40000)
	binary.BigEndian.PutUint16(seg[2:4], 9)
	switch proto {
	case ipProtoUDP:
		binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
	case ipProtoTCP:
		seg[12] = 5 << 4
		seg[13] = tcpFlagACK
	case ipProtoICMPv6:
		seg[0], seg[1] = 128, 0 // echo request
	case ipProtoICMP:
		seg[0], seg[1] = 8, 0 // echo request
	}
	for i := hdrLen; i < len(seg); i++ {
		seg[i] = byte(i)
	}
	return seg
}

// v6Packet returns an Ethernet frame holding an IPv6 packet of exactly l3Len
// bytes from src to dst.
func v6Packet(src, dst netip.Addr, proto byte, l3Len int) []byte {
	return withEth(0x86DD, ip6TCP(src, dst, proto, l4Datagram(proto, l3Len-ip6HeaderLen-l4HdrLen(proto))))
}

// v4Packet returns an Ethernet frame holding an IPv4 packet of exactly l3Len
// bytes, with ipOptions and the DF flag as given.
func v4Packet(proto byte, ipOptions []byte, df bool, l3Len int) []byte {
	var fragOff uint16
	if df {
		fragOff = ipv4FlagDF
	}
	l3 := ip4TCP(mssPodV4, mssRemoteV4, ipOptions, fragOff,
		l4Datagram(proto, l3Len-20-len(ipOptions)-l4HdrLen(proto)))
	l3[9] = proto
	binary.BigEndian.PutUint16(l3[10:12], 0)
	ihl := int(l3[0]&0x0F) * 4
	binary.BigEndian.PutUint16(l3[10:12], ^fold(onesComplementSum(0, l3[:ihl])))
	return withEth(0x0800, l3)
}

func l4HdrLen(proto byte) int {
	if proto == ipProtoTCP {
		return 20
	}
	return 8
}

// runEgressExpect runs usid_egress on pkt and requires verdict want.
func runEgressExpect(t *testing.T, objs *UsidObjects, pkt []byte, want uint32) []byte {
	t.Helper()
	ret, out, err := objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != want {
		t.Fatalf("verdict = %d, want %d", ret, want)
	}
	return out
}

// partialChecksumSpot returns where Linux would have put csum_start and
// csum_offset for the offending packet, as offsets from the start of the
// error frame: the transport header of the packet as it arrived, which
// send_too_big pushed further from the frame's start, and 16 for TCP, 6 for
// anything else.
func partialChecksumSpot(errIPHdrLen, origL4Off int, proto byte) (start, offset int) {
	offset = 6
	if proto == ipProtoTCP {
		offset = 16
	}
	push := errIPHdrLen + 76 - origL4Off - offset
	return ethHeaderLen + origL4Off + push, offset
}

// finishPartialChecksum applies what the kernel's skb_checksum_help does to a
// CHECKSUM_PARTIAL packet sent through a device without checksum offload: sum
// from start to the end, and store the folded complement at start+offset, a
// zero result stored as 0xFFFF.
func finishPartialChecksum(frame []byte, start, offset int) []byte {
	out := append([]byte(nil), frame...)
	csum := ^fold(onesComplementSum(0, out[start:]))
	if csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(out[start+offset:], csum)
	return out
}

func icmp6ChecksumValid(src, dst netip.Addr, msg []byte) bool {
	sum := onesComplementSum(0, src.AsSlice())
	sum = onesComplementSum(sum, dst.AsSlice())
	sum += uint32(len(msg)) + ipProtoICMPv6
	return fold(onesComplementSum(sum, msg)) == 0xFFFF
}

// assertTooBig6 checks out is the Packet Too Big pkt should have produced,
// sent from the gateway to sender, and that it stays valid if the kernel
// finishes the offending packet's offloaded checksum on its way out.
func assertTooBig6(t *testing.T, out, pkt []byte, sender netip.Addr, proto byte) {
	t.Helper()
	if want := ethHeaderLen + ip6HeaderLen + pmtuMsgLen; len(out) != want {
		t.Fatalf("error frame is %d bytes, want %d", len(out), want)
	}
	if !bytes.Equal(out[0:6], pkt[6:12]) || !bytes.Equal(out[6:12], pkt[0:6]) {
		t.Errorf("MACs = dst % x src % x, want the tenant's frame's swapped", out[0:6], out[6:12])
	}
	if et := binary.BigEndian.Uint16(out[12:14]); et != 0x86DD {
		t.Errorf("ethertype = %#x, want IPv6", et)
	}

	ip6 := out[ethHeaderLen:]
	if ip6[0]>>4 != 6 || binary.BigEndian.Uint16(ip6[4:6]) != pmtuMsgLen || ip6[6] != ipProtoICMPv6 || ip6[7] != 64 {
		t.Errorf("IPv6 header = % x, want version 6, payload %d, next header ICMPv6, hop limit 64",
			ip6[:8], pmtuMsgLen)
	}
	src, _ := netip.AddrFromSlice(ip6[8:24])
	dst, _ := netip.AddrFromSlice(ip6[24:40])
	if src != pmtuGW6 || dst != sender {
		t.Errorf("error is %v -> %v, want %v -> %v", src, dst, pmtuGW6, sender)
	}

	msg := ip6[ip6HeaderLen:]
	if msg[0] != 2 || msg[1] != 0 {
		t.Errorf("ICMPv6 type/code = %d/%d, want Packet Too Big (2/0)", msg[0], msg[1])
	}
	if mtu := binary.BigEndian.Uint32(msg[4:8]); mtu != testEncapMTU {
		t.Errorf("MTU = %d, want %d: the largest packet that fits once encapsulated", mtu, testEncapMTU)
	}
	if !icmp6ChecksumValid(src, dst, msg) {
		t.Error("ICMPv6 checksum is invalid")
	}

	start, offset := partialChecksumSpot(ip6HeaderLen, ip6HeaderLen, proto)
	if finished := finishPartialChecksum(out, start, offset); !bytes.Equal(finished, out) {
		t.Errorf("finishing an offloaded checksum changed the error at byte %d:\n got % x\nwant % x",
			start+offset, finished[start+offset:start+offset+2], out[start+offset:start+offset+2])
	}
}

// assertFragNeeded4 is assertTooBig6 for an IPv4 tenant.
func assertFragNeeded4(t *testing.T, out, pkt []byte, proto byte) {
	t.Helper()
	if want := ethHeaderLen + 20 + pmtuMsgLen; len(out) != want {
		t.Fatalf("error frame is %d bytes, want %d", len(out), want)
	}
	if !bytes.Equal(out[0:6], pkt[6:12]) || !bytes.Equal(out[6:12], pkt[0:6]) {
		t.Errorf("MACs = dst % x src % x, want the tenant's frame's swapped", out[0:6], out[6:12])
	}
	if et := binary.BigEndian.Uint16(out[12:14]); et != 0x0800 {
		t.Errorf("ethertype = %#x, want IPv4", et)
	}

	ip4 := out[ethHeaderLen:]
	if ip4[0] != 0x45 || binary.BigEndian.Uint16(ip4[2:4]) != 20+pmtuMsgLen || ip4[8] != 64 || ip4[9] != ipProtoICMP {
		t.Errorf("IPv4 header = % x, want IHL 5, length %d, TTL 64, protocol ICMP", ip4[:20], 20+pmtuMsgLen)
	}
	if fold(onesComplementSum(0, ip4[:20])) != 0xFFFF {
		t.Error("IPv4 header checksum is invalid")
	}
	src, _ := netip.AddrFromSlice(ip4[12:16])
	dst, _ := netip.AddrFromSlice(ip4[16:20])
	if src != pmtuGW4 || dst != mssPodV4 {
		t.Errorf("error is %v -> %v, want %v -> %v", src, dst, pmtuGW4, mssPodV4)
	}

	msg := ip4[20:]
	if msg[0] != 3 || msg[1] != 4 {
		t.Errorf("ICMP type/code = %d/%d, want Fragmentation Needed (3/4)", msg[0], msg[1])
	}
	unused, mtu := binary.BigEndian.Uint16(msg[4:6]), binary.BigEndian.Uint16(msg[6:8])
	if unused != 0 || mtu != testEncapMTU {
		t.Errorf("unused/next-hop MTU = %d/%d, want 0/%d", unused, mtu, testEncapMTU)
	}
	if fold(onesComplementSum(0, msg)) != 0xFFFF {
		t.Error("ICMP checksum is invalid")
	}

	origIHL := int(pkt[ethHeaderLen]&0x0F) * 4
	start, offset := partialChecksumSpot(20, origIHL, proto)
	if finished := finishPartialChecksum(out, start, offset); !bytes.Equal(finished, out) {
		t.Errorf("finishing an offloaded checksum changed the error at byte %d", start+offset)
	}
}

// assertQuote checks the error quotes the offending packet's first 68 bytes as
// the tenant sent it.
func assertQuote(t *testing.T, out []byte, errIPHdrLen int, want []byte) {
	t.Helper()
	quote := out[ethHeaderLen+errIPHdrLen+8 : ethHeaderLen+errIPHdrLen+8+68]
	if !bytes.Equal(quote, want[:68]) {
		t.Errorf("quote differs from the offending packet:\n got % x\nwant % x", quote, want[:68])
	}
}

// TestPMTU_IPv6TooBigGetsPacketTooBig is the issue's core case for an IPv6
// tenant, for each transport the offload layout depends on: a packet one byte
// over the limit, and a full 1500-byte one, get a Packet Too Big carrying the
// limit.
func TestPMTU_IPv6TooBigGetsPacketTooBig(t *testing.T) {
	for _, proto := range []byte{ipProtoUDP, ipProtoTCP, ipProtoICMPv6} {
		for _, size := range []int{testEncapMTU + 1, 1500} {
			objs := pmtuFixture(t)
			pkt := v6Packet(mssPodV6, mssRemoteV6, proto, size)
			out := runEgressExpect(t, objs, pkt, tcActRedirect)
			assertTooBig6(t, out, pkt, mssPodV6, proto)
			assertQuote(t, out, ip6HeaderLen, pkt[ethHeaderLen:])
			assertPMTUStats(t, objs, map[uint32]uint64{PMTUStatTooBigSentIPv6: 1})
			if got := sumPerCPU(t, objs.DropReasons, DropReasonFibFragNeeded); got != 0 {
				t.Errorf("proto %d, %d bytes: drop_reasons[fib_frag_needed] = %d, want 0 for a packet answered",
					proto, size, got)
			}
		}
	}
}

// TestPMTU_IPv4TooBigGetsFragNeeded covers an IPv4 tenant, with and without
// IP options, which move the transport header and so the offload layout.
func TestPMTU_IPv4TooBigGetsFragNeeded(t *testing.T) {
	for _, opts := range [][]byte{nil, {1, 1, 1, 0}, bytes.Repeat([]byte{1}, 40)} {
		for _, proto := range []byte{ipProtoUDP, ipProtoTCP} {
			objs := pmtuFixture(t)
			pkt := v4Packet(proto, opts, true, 1500)
			out := runEgressExpect(t, objs, pkt, tcActRedirect)
			assertFragNeeded4(t, out, pkt, proto)
			assertQuote(t, out, 20, pkt[ethHeaderLen:])
			assertPMTUStats(t, objs, map[uint32]uint64{PMTUStatFragNeededSentIPv4: 1})
		}
	}
}

// TestPMTU_PacketAtLimitIsEncapsulated is the boundary: a packet exactly the
// limit fits once encapsulated and goes on unchanged.
func TestPMTU_PacketAtLimitIsEncapsulated(t *testing.T) {
	objs := pmtuFixture(t)
	pkt := v6Packet(mssPodV6, mssRemoteV6, ipProtoUDP, testEncapMTU)
	inner := runEgress(t, objs, pkt)
	if !bytes.Equal(inner, pkt[ethHeaderLen:]) {
		t.Error("a packet at the limit was changed on its way to the fabric")
	}
	pkt4 := v4Packet(ipProtoUDP, nil, true, testEncapMTU)
	runEgress(t, objs, pkt4)
	assertPMTUStats(t, objs, nil)
}

// TestPMTU_OffWhenUnconfigured checks a node whose control plane has not
// written encap_mtu_table yet behaves as before the check existed.
func TestPMTU_OffWhenUnconfigured(t *testing.T) {
	objs := pmtuFixture(t)
	setEncapMTU(t, objs, 0)
	runEgress(t, objs, v6Packet(mssPodV6, mssRemoteV6, ipProtoUDP, 1500))
	assertPMTUStats(t, objs, nil)
}

// TestPMTU_DroppedWithoutError covers every oversized packet that gets no
// error. Each is dropped, counted under its own result, and counted as
// fib_frag_needed in drop_reasons.
func TestPMTU_DroppedWithoutError(t *testing.T) {
	icmp6Error := func() []byte {
		pkt := v6Packet(mssPodV6, mssRemoteV6, ipProtoICMPv6, 1500)
		pkt[ethHeaderLen+ip6HeaderLen] = 1 // Destination Unreachable
		return pkt
	}
	icmp4Error := func() []byte {
		pkt := v4Packet(ipProtoICMP, nil, true, 1500)
		pkt[ethHeaderLen+20] = 11 // Time Exceeded
		return pkt
	}

	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, objs *UsidObjects)
		pkt   []byte
		stat  uint32
	}{
		{
			name: "IPv4 without DF",
			pkt:  v4Packet(ipProtoUDP, nil, false, 1500),
			stat: PMTUStatDroppedNoDF,
		},
		{name: "ICMPv6 error", pkt: icmp6Error(), stat: PMTUStatDroppedICMPError},
		{name: "ICMPv4 error", pkt: icmp4Error(), stat: PMTUStatDroppedICMPError},
		{
			name: "no gateway entry",
			setup: func(t *testing.T, objs *UsidObjects) {
				if err := objs.TenantGwTable.Delete(uint32(1)); err != nil {
					t.Fatalf("delete tenant_gw_table entry: %v", err)
				}
			},
			pkt:  v6Packet(mssPodV6, mssRemoteV6, ipProtoUDP, 1500),
			stat: PMTUStatNoGateway,
		},
		{
			name: "no gateway in the packet's family",
			setup: func(t *testing.T, objs *UsidObjects) {
				if err := objs.TenantGwTable.Put(uint32(1), UsidTenantGwValue{Gw6: pmtuGW6.As16()}); err != nil {
					t.Fatalf("populate tenant_gw_table: %v", err)
				}
			},
			pkt:  v4Packet(ipProtoUDP, nil, true, 1500),
			stat: PMTUStatNoGateway,
		},
		{
			name:  "rate limited",
			setup: drainPMTUBucket,
			pkt:   v6Packet(mssPodV6, mssRemoteV6, ipProtoUDP, 1500),
			stat:  PMTUStatRateLimited,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			objs := pmtuFixture(t)
			if tt.setup != nil {
				tt.setup(t, objs)
			}
			runEgressExpect(t, objs, tt.pkt, tcActShot)
			assertPMTUStats(t, objs, map[uint32]uint64{tt.stat: 1})
			if got := sumPerCPU(t, objs.DropReasons, DropReasonFibFragNeeded); got != 1 {
				t.Errorf("drop_reasons[fib_frag_needed] = %d, want 1", got)
			}
		})
	}
}

// pmtuBucket mirrors struct pmtu_icmp_bucket.
type pmtuBucket struct {
	LastNs   uint64
	CreditNs uint64
}

// drainPMTUBucket empties every CPU's bucket and stamps it in the far future,
// so no credit accrues during the test.
func drainPMTUBucket(t *testing.T, objs *UsidObjects) {
	t.Helper()
	n, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible CPUs: %v", err)
	}
	buckets := make([]pmtuBucket, n)
	for i := range buckets {
		buckets[i] = pmtuBucket{LastNs: math.MaxUint64}
	}
	if err := objs.PmtuIcmpBucket.Put(uint32(0), buckets); err != nil {
		t.Fatalf("drain pmtu_icmp_bucket: %v", err)
	}
}

// TestPMTU_RateLimitAllowsBurst checks the bucket admits a burst and then
// refuses, rather than refusing everything or nothing.
func TestPMTU_RateLimitAllowsBurst(t *testing.T) {
	objs := pmtuFixture(t)
	pkt := v6Packet(mssPodV6, mssRemoteV6, ipProtoUDP, 1500)
	const burst = 100
	for i := range burst {
		if ret, _, err := objs.UsidEgress.Test(pkt); err != nil || ret != tcActRedirect {
			t.Fatalf("error %d of the burst: verdict %d, err %v; want it sent", i+1, ret, err)
		}
	}
	// Each refill takes a millisecond. Several more in a row cannot all be
	// admitted, however slow the test runs.
	refused := 0
	for range 50 {
		if ret, _, _ := objs.UsidEgress.Test(pkt); ret == tcActShot {
			refused++
		}
	}
	if refused == 0 {
		t.Error("no error refused after the burst, want the rate limit to apply")
	}
}

// TestPMTU_NPTv6SourceIsTranslatedBack checks a tenant whose VRF uses NPTv6
// gets the error at its own address. By the time the check runs the source has
// already been translated to the public prefix, which the tenant does not
// hold; the error and its quote must name the address the tenant sent from.
func TestPMTU_NPTv6SourceIsTranslatedBack(t *testing.T) {
	objs := pmtuFixture(t)
	vrfKey, err := uformat.NewVRFKey(0x123456, 0x210)
	if err != nil {
		t.Fatalf("NewVRFKey: %v", err)
	}
	if err := objs.Nptv6Table.Put(uint64(vrfKey), UsidNptv6Value{
		UlaPrefix:    nptv6Prefix48(t, "fd01:203:405::"),
		PublicPrefix: nptv6Prefix48(t, "2001:db8:1::"),
		PrefixLen:    48,
		Adjustment:   0xD54F,
	}); err != nil {
		t.Fatalf("populate nptv6_table: %v", err)
	}

	pod := netip.MustParseAddr("fd01:203:405:1::1234")
	pkt := v6Packet(pod, mssRemoteV6, ipProtoUDP, 1500)
	out := runEgressExpect(t, objs, pkt, tcActRedirect)
	assertTooBig6(t, out, pkt, pod, ipProtoUDP)
	assertQuote(t, out, ip6HeaderLen, pkt[ethHeaderLen:])
}
