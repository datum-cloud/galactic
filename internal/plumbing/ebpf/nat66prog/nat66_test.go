// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66prog

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	xdpPass = 2
	xdpDrop = 1
	xdpTx   = 3

	ipprotoUDP = 17

	// encappedSrcPort/encappedDstPort are the backend's own source port
	// and the tenant flow's destination port in every buildEncappedUDPPacket
	// fixture below -- see that function's own doc comment.
	encappedSrcPort = 40000
	encappedDstPort = 443
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to load BPF programs and maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

func loadObjects(t *testing.T) *Nat66Objects {
	t.Helper()

	var objs Nat66Objects
	if err := LoadNat66Objects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load objects: verifier rejected program:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() {
		if err := objs.Close(); err != nil {
			t.Errorf("close objects: %v", err)
		}
	})
	return &objs
}

func sumPerCPU(t *testing.T, m *ebpf.Map, index uint32) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := m.Lookup(index, &perCPU); err != nil {
		t.Fatalf("lookup drop_reasons[%d]: %v", index, err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

const ethLen = 14
const ip6Len = 40
const udpLen = 8

// buildUDPPacket constructs a minimal Ethernet+IPv6+UDP frame with a real,
// correctly-computed UDP checksum -- needed here (unlike edgedsr_test.go)
// because this program actually rewrites the checksum via bpf_csum_diff,
// so tests need a starting value to verify the incremental update against.
func buildUDPPacket(t *testing.T, dst, src netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()

	udp := make([]byte, udpLen+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udp6Checksum(src.As16(), dst.As16(), udp))

	pkt := make([]byte, 0, ethLen+ip6Len+len(udp))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x86, 0xDD)

	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	udpTotalLen := uint16(len(udp))
	pkt = append(pkt, byte(udpTotalLen>>8), byte(udpTotalLen))
	pkt = append(pkt, ipprotoUDP)
	pkt = append(pkt, 64)
	srcBytes := src.As16()
	pkt = append(pkt, srcBytes[:]...)
	dstBytes := dst.As16()
	pkt = append(pkt, dstBytes[:]...)
	pkt = append(pkt, udp...)

	return pkt
}

// udp6Checksum is the same independent reference implementation
// internal/plumbing/ebpf/prog/usid_test.go's identical helper is -- used
// only to build/verify checksums, not to exercise anything in nat66.c.
func udp6Checksum(src, dst [16]byte, udpHeaderAndPayload []byte) uint16 {
	var sum uint32
	add16 := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add16(src[:])
	add16(dst[:])
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(udpHeaderAndPayload)))
	add16(lenBuf[:])
	sum += uint32(ipprotoUDP)
	add16(udpHeaderAndPayload)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildEncappedUDPPacket wraps an inner UDP packet in a plain
// IPv6-in-IPv6 outer header (SEG6_IPTUN_MODE_ENCAP_RED's wire format,
// matching internal/plumbing/srv6/egress.go's RouteEgressAdd) -- the shape
// a tenant's own outbound egress packet actually arrives in.
//
// srcPort/dstPort are always encappedSrcPort/encappedDstPort across every
// caller in this file (unparam) -- not parameterized further since no
// test here needs different backend-side ports.
func buildEncappedUDPPacket(t *testing.T, outerDst, outerSrc, innerSrc, innerDst netip.Addr,
	payload []byte,
) []byte {
	t.Helper()
	// drop the inner packet's own eth header
	inner := buildUDPPacket(t, innerDst, innerSrc, encappedSrcPort, encappedDstPort, payload)[ethLen:]

	pkt := make([]byte, 0, ethLen+ip6Len+len(inner))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x86, 0xDD)

	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	payloadLen := uint16(len(inner))
	pkt = append(pkt, byte(payloadLen>>8), byte(payloadLen))
	pkt = append(pkt, 41) // outer nexthdr = IPv6-in-IPv6
	pkt = append(pkt, 64)
	outerSrcBytes := outerSrc.As16()
	pkt = append(pkt, outerSrcBytes[:]...)
	outerDstBytes := outerDst.As16()
	pkt = append(pkt, outerDstBytes[:]...)
	pkt = append(pkt, inner...)

	return pkt
}

// TestNat66Ingress_UnclaimedTrafficPassesThrough covers the common case:
// traffic addressed to neither shard_pub_addr nor this shard's own
// shard_sid locator must pass through completely unmodified.
func TestNat66Ingress_UnclaimedTrafficPassesThrough(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	if err := objs.ShardConfigTable.Put(uint32(0), Nat66ShardConfig{
		ShardSid:     netip.MustParseAddr("fc00:1:2::1").As16(),
		ShardPubAddr: netip.MustParseAddr("2001:db8:9999::1").As16(),
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	pkt := buildUDPPacket(t, netip.MustParseAddr("2001:db8::9999"),
		netip.MustParseAddr("2001:db8:ffff::1"), 5000, 443, []byte("hi"))
	ret, out, err := objs.Nat66Ingress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet mutated on a miss:\n in: % x\nout: % x", pkt, out)
	}
}

// TestNat66Ingress_ForwardSNATsAndPreservesChecksum covers handle_forward:
// a tenant's own SRv6-encapsulated egress packet must be decapsulated,
// SNAT'd to shard_pub_addr with an allocated port, and passed through
// (XDP_PASS) with a checksum that verifies against an independent full
// recompute -- not just "the verifier accepted it".
func TestNat66Ingress_ForwardSNATsAndPreservesChecksum(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	if err := objs.ShardConfigTable.Put(uint32(0), Nat66ShardConfig{
		ShardSid: shardSID.As16(), ShardPubAddr: shardPub.As16(),
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	backendAddr := netip.MustParseAddr("fd20:60::5")
	backendUSID := netip.MustParseAddr("fc00:3:4::a1b2")
	destAddr := netip.MustParseAddr("2001:db8:9998::1")
	const destPort = 443

	// The Argument nibble (bits 69-80 of shardSID, this uSID's low bits)
	// carries the requesting tenant's VRFID -- 0x123 here, arbitrary but
	// nonzero (Argument 0 is reserved elsewhere in this codebase).
	shardSIDWithArg := shardSID.As16()
	shardSIDWithArg[8] = (shardSIDWithArg[8] & 0xF0) | 0x01
	shardSIDWithArg[9] = 0x23

	payload := []byte("egress payload")
	pkt := buildEncappedUDPPacket(t, netip.AddrFrom16(shardSIDWithArg), backendUSID,
		backendAddr, destAddr, payload)

	ret, out, err := objs.Nat66Ingress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("verdict = %d, want XDP_PASS (%d) -- SNAT'd traffic must be handed to the kernel's "+
			"own routing, not dropped or re-encapsulated", ret, xdpPass)
	}

	// Post-decap layout: eth(14) + ip6(40) + udp -- daddr unchanged
	// (destAddr), saddr rewritten to shardPub, source port rewritten to
	// the allocated masquerade port.
	const saddrOffset = ethLen + 8
	const daddrOffset = ethLen + 24
	const udpOffset = ethLen + ip6Len

	var gotSaddr, gotDaddr [16]byte
	copy(gotSaddr[:], out[saddrOffset:saddrOffset+16])
	copy(gotDaddr[:], out[daddrOffset:daddrOffset+16])
	if gotSaddr != shardPub.As16() {
		t.Errorf("saddr after SNAT = %x, want %x (shard_pub_addr)", gotSaddr, shardPub.As16())
	}
	if gotDaddr != destAddr.As16() {
		t.Errorf("daddr changed unexpectedly: got %x, want %x (untouched)", gotDaddr, destAddr.As16())
	}

	gotSrcPort := binary.BigEndian.Uint16(out[udpOffset : udpOffset+2])
	gotDstPort := binary.BigEndian.Uint16(out[udpOffset+2 : udpOffset+4])
	if gotDstPort != destPort {
		t.Errorf("dest port changed unexpectedly: got %d, want %d", gotDstPort, destPort)
	}
	if gotSrcPort < 32768 || gotSrcPort >= 32768+28000 {
		t.Errorf("allocated masquerade port %d outside the configured PAT range", gotSrcPort)
	}

	gotUDP := out[udpOffset:]
	gotCsum := binary.BigEndian.Uint16(gotUDP[6:8])
	zeroCsum := append([]byte{}, gotUDP...)
	zeroCsum[6], zeroCsum[7] = 0, 0
	wantCsum := udp6Checksum(shardPub.As16(), destAddr.As16(), zeroCsum)
	if gotCsum != wantCsum {
		t.Errorf("UDP checksum after SNAT = %#04x, want %#04x (independent full recompute)", gotCsum, wantCsum)
	}

	// A second packet on the identical flow must reuse the identical
	// masquerade port (conn_table hit, not a fresh allocation) -- the
	// property that makes a flow's translation stable for its whole
	// lifetime.
	pkt2 := buildEncappedUDPPacket(t, netip.AddrFrom16(shardSIDWithArg), backendUSID,
		backendAddr, destAddr, []byte("second packet"))
	_, out2, err := objs.Nat66Ingress.Test(pkt2)
	if err != nil {
		t.Fatalf("program test-run (2nd packet): %v", err)
	}
	gotSrcPort2 := binary.BigEndian.Uint16(out2[udpOffset : udpOffset+2])
	if gotSrcPort2 != gotSrcPort {
		t.Errorf("masquerade port changed across packets on the same flow: %d then %d", gotSrcPort, gotSrcPort2)
	}
}

// TestNat66Ingress_DifferentNodeIDPassesThrough proves locator_matches'
// deliberate 64-bit (Block+Node-ID) granularity does NOT accidentally
// widen to a full 128-bit match: two uSIDs sharing shard_sid's Block but
// not its Node-ID must never be treated as this shard's own traffic,
// regardless of what the low 64 bits (Function+Argument) happen to
// contain. This is the actual boundary a real deployment must keep
// disjoint -- see locator_matches' own doc comment for the live
// incident (a shard reusing its co-located compute node's own Node-ID)
// this same 64-bit match cannot, by itself, detect or prevent; this test
// only proves the match's own stated granularity is what's implemented,
// not a fix for that allocation-level constraint.
func TestNat66Ingress_DifferentNodeIDPassesThrough(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	if err := objs.ShardConfigTable.Put(uint32(0), Nat66ShardConfig{
		ShardSid: shardSID.As16(), ShardPubAddr: shardPub.As16(),
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	// Same Block (bytes 0-5) as shardSID, but a different Node-ID (bytes
	// 6-7) -- a different node's own uSID space entirely, sharing only
	// the site's locator.
	otherUSID := shardSID.As16()
	otherUSID[6] = 0x00
	otherUSID[7] = 0x09

	backendAddr := netip.MustParseAddr("fd20:60::5")
	backendUSID := netip.MustParseAddr("fc00:3:4::a1b2")
	destAddr := netip.MustParseAddr("2001:db8:9998::1")

	pkt := buildEncappedUDPPacket(t, netip.AddrFrom16(otherUSID), backendUSID,
		backendAddr, destAddr, []byte("a different node's own uSID space"))

	ret, out, err := objs.Nat66Ingress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("verdict = %d, want XDP_PASS (%d) -- this is a different Node-ID, not this shard's own traffic",
			ret, xdpPass)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet mutated on a Node-ID mismatch:\n in: % x\nout: % x", pkt, out)
	}
}

// TestNat66Ingress_ReturnUnNATsAndReencapsulates covers handle_return: a
// reply from the internet, addressed to shard_pub_addr:allocated_port,
// must be un-SNAT'd back to the tenant backend's own view and
// re-encapsulated via SRv6 toward that backend's worker node.
func TestNat66Ingress_ReturnUnNATsAndReencapsulates(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	if err := objs.ShardConfigTable.Put(uint32(0), Nat66ShardConfig{
		ShardSid: shardSID.As16(), ShardPubAddr: shardPub.As16(),
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	backendAddr := netip.MustParseAddr("fd20:60::5")
	backendUSID := netip.MustParseAddr("fc00:3:4::a1b2")
	destAddr := netip.MustParseAddr("2001:db8:9998::1")
	const backendPort, destPort = 40000, 443

	shardSIDWithArg := shardSID.As16()
	shardSIDWithArg[8] = (shardSIDWithArg[8] & 0xF0) | 0x01
	shardSIDWithArg[9] = 0x23

	// First, run a forward packet to populate conn_table (both rows) and
	// learn the allocated masquerade port.
	fwdPkt := buildEncappedUDPPacket(t, netip.AddrFrom16(shardSIDWithArg), backendUSID,
		backendAddr, destAddr, []byte("out"))
	_, fwdOut, err := objs.Nat66Ingress.Test(fwdPkt)
	if err != nil {
		t.Fatalf("forward program test-run: %v", err)
	}
	const udpOffset = ethLen + ip6Len
	masqPort := binary.BigEndian.Uint16(fwdOut[udpOffset : udpOffset+2])

	// Now the reply: from destAddr:destPort, to shardPub:masqPort.
	replyPkt := buildUDPPacket(t, shardPub, destAddr, destPort, masqPort, []byte("reply"))

	ret, out, err := objs.Nat66Ingress.Test(replyPkt)
	if err != nil {
		t.Fatalf("return program test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d) (FIB lookup against a synthetic backend uSID must "+
			"fail, not succeed, on this test host)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonNat66FibLookupFailed); got != 1 {
		t.Errorf("drop_reasons[fib_lookup_failed] = %d, want 1 (push_outer_header must have run)", got)
	}

	// push_outer_header writes the outer header (and handle_return already
	// rewrote the un-SNAT'd inner daddr/dport) before the FIB lookup, so
	// both are already visible in the output bytes despite the drop.
	const outerDaddrOffset = ethLen + 24
	const outerSaddrOffset = ethLen + 8
	var gotOuterDaddr, gotOuterSaddr [16]byte
	copy(gotOuterDaddr[:], out[outerDaddrOffset:outerDaddrOffset+16])
	copy(gotOuterSaddr[:], out[outerSaddrOffset:outerSaddrOffset+16])
	if gotOuterDaddr != backendUSID.As16() {
		t.Errorf("outer daddr = %x, want %x (backend's own worker-node uSID)", gotOuterDaddr, backendUSID.As16())
	}
	if gotOuterSaddr != shardSID.As16() {
		t.Errorf("outer saddr = %x, want %x (this shard's own shard_sid)", gotOuterSaddr, shardSID.As16())
	}

	// Regression guard for the two real bugs found via live-kernel
	// investigation (see edgedsr.c's identical push_outer_header fixes):
	// version nibble must be 6, and payload_len must cover the inner
	// packet's own IPv6 header (40 bytes) plus its own payload, not just
	// the payload alone.
	if gotVersion := out[ethLen] >> 4; gotVersion != 6 {
		t.Errorf("outer header IPv6 version = %d, want 6", gotVersion)
	}
	const replyPayloadLen = len("reply")
	gotOuterPayloadLen := binary.BigEndian.Uint16(out[ethLen+4 : ethLen+6])
	wantOuterPayloadLen := uint16(ip6Len + udpLen + replyPayloadLen)
	if gotOuterPayloadLen != wantOuterPayloadLen {
		t.Errorf("outer header payload_len = %d, want %d (inner ip6 header + inner UDP + payload)",
			gotOuterPayloadLen, wantOuterPayloadLen)
	}

	const innerDaddrOffset = ethLen + ip6Len + 24
	const innerUDPOffset = ethLen + ip6Len + ip6Len
	var gotInnerDaddr [16]byte
	copy(gotInnerDaddr[:], out[innerDaddrOffset:innerDaddrOffset+16])
	if gotInnerDaddr != backendAddr.As16() {
		t.Errorf("inner daddr after un-SNAT = %x, want %x (tenant backend's own address)",
			gotInnerDaddr, backendAddr.As16())
	}
	gotInnerDstPort := binary.BigEndian.Uint16(out[innerUDPOffset+2 : innerUDPOffset+4])
	if gotInnerDstPort != backendPort {
		t.Errorf("inner dest port after un-SNAT = %d, want %d (tenant backend's own port)",
			gotInnerDstPort, backendPort)
	}
}

// TestNat66Ingress_ReturnWithNoConnDropped covers the claimed-address
// fail-closed contract: a reply to shard_pub_addr with no matching
// conn_table row must drop, not pass through (this address is claimed).
func TestNat66Ingress_ReturnWithNoConnDropped(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	if err := objs.ShardConfigTable.Put(uint32(0), Nat66ShardConfig{
		ShardSid:     netip.MustParseAddr("fc00:1:2::1").As16(),
		ShardPubAddr: shardPub.As16(),
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	pkt := buildUDPPacket(t, shardPub, netip.MustParseAddr("2001:db8:9998::1"), 443, 55555, []byte("x"))
	ret, _, err := objs.Nat66Ingress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonNat66NoReturnConn); got != 1 {
		t.Errorf("drop_reasons[no_return_conn] = %d, want 1", got)
	}
}
