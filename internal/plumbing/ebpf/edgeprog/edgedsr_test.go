// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

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
	ipprotoTCP = 6
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

func loadObjects(t *testing.T) *EdgedsrObjects {
	t.Helper()

	var objs EdgedsrObjects
	if err := LoadEdgedsrObjects(&objs, nil); err != nil {
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
const tcpLen = 20

// l4HeaderLen is the wire length of the L4 header buildL4Packet writes for
// proto. The datapath itself reads only the first four bytes of either (struct
// edge_l4ports), but a receiver and this test's own offset arithmetic both need
// the real thing.
func l4HeaderLen(proto uint8) int {
	if proto == ipprotoTCP {
		return tcpLen
	}
	return udpLen
}

// buildL4Packet constructs a minimal Ethernet+IPv6+TCP or +UDP frame --
// vip_table matches on protocol as well as address and port, so both of the
// two protocols it can hold are worth synthesizing.
func buildL4Packet(t *testing.T, proto uint8, dst, src netip.Addr, srcPort, dstPort uint16,
	payload []byte) []byte {
	t.Helper()

	l4Len := l4HeaderLen(proto)
	pkt := make([]byte, 0, ethLen+ip6Len+l4Len+len(payload))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x86, 0xDD)

	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	l4TotalLen := uint16(l4Len + len(payload))
	pkt = append(pkt, byte(l4TotalLen>>8), byte(l4TotalLen))
	pkt = append(pkt, proto)
	pkt = append(pkt, 64)
	srcBytes := src.As16()
	pkt = append(pkt, srcBytes[:]...)
	dstBytes := dst.As16()
	pkt = append(pkt, dstBytes[:]...)

	pkt = append(pkt, byte(srcPort>>8), byte(srcPort))
	pkt = append(pkt, byte(dstPort>>8), byte(dstPort))
	if proto == ipprotoTCP {
		pkt = append(pkt, 0x00, 0x00, 0x00, 0x01) // sequence
		pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // acknowledgement
		pkt = append(pkt, 0x50, 0x02)             // data offset 5 words, SYN
		pkt = append(pkt, 0xff, 0xff)             // window
		pkt = append(pkt, 0x00, 0x00)             // checksum, unchecked/untouched by this program
		pkt = append(pkt, 0x00, 0x00)             // urgent pointer
	} else {
		pkt = append(pkt, byte(l4TotalLen>>8), byte(l4TotalLen))
		pkt = append(pkt, 0x00, 0x00) // checksum, unchecked/untouched by this program
	}
	pkt = append(pkt, payload...)

	return pkt
}

func vipKey(proto uint8, port uint16, vip netip.Addr) EdgedsrVipKey {
	return EdgedsrVipKey{Proto: proto, Port: bswap16(port), Vip: vip.As16()}
}

func bswap16(v uint16) uint16 { return v<<8 | v>>8 }

// TestEdgeLB_NonVIPPassesThrough covers the common miss case: traffic to
// an address/port this gateway holds no vip_table entry for must pass
// through completely unmodified -- XDP_PASS, no drop counted.
func TestEdgeLB_NonVIPPassesThrough(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8::100")
	other := netip.MustParseAddr("2001:db8::200")
	if err := objs.VipTable.Put(vipKey(ipprotoUDP, 443, other), EdgedsrVipValue{BackendCount: 1}); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}

	pkt := buildL4Packet(t, ipprotoUDP, vip, netip.MustParseAddr("2001:db8:ffff::1"), 5000, 443, []byte("hi"))
	ret, out, err := objs.EdgeLb.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet mutated on a vip_table miss:\n in: % x\nout: % x", pkt, out)
	}
}

// TestEdgeLB_EmptyBackendListDropped covers a claimed VIP (rule exists)
// with no backends configured -- must drop, counted, not silently pass.
func TestEdgeLB_EmptyBackendListDropped(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8::100")
	if err := objs.VipTable.Put(vipKey(ipprotoUDP, 443, vip), EdgedsrVipValue{BackendCount: 0}); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}

	pkt := buildL4Packet(t, ipprotoUDP, vip, netip.MustParseAddr("2001:db8:ffff::1"), 5000, 443, []byte("hi"))
	ret, _, err := objs.EdgeLb.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonEmptyBackendList); got != 1 {
		t.Errorf("drop_reasons[empty_backend_list] = %d, want 1", got)
	}
}

// TestEdgeLB_ForwardsPacketUnmodifiedToBackend is the core DSR property
// test (design plan §0): a claimed VIP with a real backend must push an
// SRv6 outer header addressed to that backend's own uSID, with the inner
// packet carried through *completely unmodified* -- no DNAT, no SNAT, no
// checksum touch. As in the analogous usid.c tests, the FIB lookup itself
// still fails here (no real route to the synthetic backend uSID exists on
// the test host), but reaching DROP_REASON_FIB_LOOKUP_FAILED -- with the
// outer header and untouched inner packet already visible in the output
// bytes, since push_outer_header writes both before checking the FIB
// result -- is exactly the evidence this test needs.
func TestEdgeLB_ForwardsPacketUnmodifiedToBackend(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8::100")
	client := netip.MustParseAddr("2001:db8:ffff::1")
	backendAddr := netip.MustParseAddr("fd20:60::5")
	backendUSID := netip.MustParseAddr("fc00:1:2::a1b2")
	encapSrc := netip.MustParseAddr("fc00:0:2::1")

	var value EdgedsrVipValue
	value.BackendCount = 1
	value.Backends[0] = EdgedsrBackend{Addr: backendAddr.As16(), Port: bswap16(30080), Usid: backendUSID.As16()}
	// Every slot points at the (only) backend index 0 -- a real
	// multi-backend Maglev table is internal/maglev's own concern
	// (already tested there); this eBPF-side test only needs to prove the
	// lookup-then-encap mechanism, not the table-construction algorithm.
	for i := range value.MaglevTable {
		value.MaglevTable[i] = 0
	}
	if err := objs.VipTable.Put(vipKey(ipprotoUDP, 443, vip), value); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}
	if err := objs.EncapConfigTable.Put(uint32(0), EdgedsrEncapConfig{EncapSrc: encapSrc.As16()}); err != nil {
		t.Fatalf("populate encap_config_table: %v", err)
	}

	payload := []byte("hello, backend")
	pkt := buildL4Packet(t, ipprotoUDP, vip, client, 5000, 443, payload)

	ret, out, err := objs.EdgeLb.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d) (FIB lookup against a synthetic uSID must fail, not succeed)",
			ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed); got != 1 {
		t.Errorf("drop_reasons[fib_lookup_failed] = %d, want 1 (push_outer_header must have run)", got)
	}

	// Post-push layout: eth(14) + outer ip6(40) + <unmodified original
	// packet from its own eth(14) onward>. The outer header's daddr must
	// be the backend's uSID; the inner packet, starting right after, must
	// be byte-identical to the client's own original packet.
	const outerDaddrOffset = ethLen + 24
	if len(out) < outerDaddrOffset+16 {
		t.Fatalf("output packet too short (%d bytes)", len(out))
	}
	var gotOuterDaddr [16]byte
	copy(gotOuterDaddr[:], out[outerDaddrOffset:outerDaddrOffset+16])
	if wantOuterDaddr := backendUSID.As16(); gotOuterDaddr != wantOuterDaddr {
		t.Errorf("outer daddr = %x, want %x (backend uSID)", gotOuterDaddr, wantOuterDaddr)
	}
	var gotOuterSaddr [16]byte
	copy(gotOuterSaddr[:], out[ethLen+8:ethLen+24])
	if wantOuterSaddr := encapSrc.As16(); gotOuterSaddr != wantOuterSaddr {
		t.Errorf("outer saddr = %x, want %x (this node's own encap_src)", gotOuterSaddr, wantOuterSaddr)
	}

	// The outer header must be valid IPv6 on the wire: version nibble ==
	// 6, and payload_len covering the *entire* inner packet (its own
	// 40-byte IPv6 header plus its own payload), not just the inner
	// payload alone. Both were real bugs found via live-kernel
	// investigation (a synthetic BPF_PROG_TEST_RUN packet doesn't care,
	// but a real receiver parsing this as wire-format IPv6 does) --
	// regression-guarded here so they can't silently return.
	if gotVersion := out[ethLen] >> 4; gotVersion != 6 {
		t.Errorf("outer header IPv6 version = %d, want 6", gotVersion)
	}
	gotOuterPayloadLen := binary.BigEndian.Uint16(out[ethLen+4 : ethLen+6])
	wantOuterPayloadLen := uint16(ip6Len + l4HeaderLen(ipprotoUDP) + len(payload))
	if gotOuterPayloadLen != wantOuterPayloadLen {
		t.Errorf("outer header payload_len = %d, want %d (inner ip6 header + inner payload)",
			gotOuterPayloadLen, wantOuterPayloadLen)
	}

	const innerOffset = ethLen + ip6Len
	gotInner := out[innerOffset:]
	wantInner := pkt[ethLen:] // the original packet's own IPv6 header onward, byte-for-byte
	if string(gotInner) != string(wantInner) {
		t.Errorf("inner packet was modified -- DSR must forward the client's packet completely "+
			"untouched:\n got: % x\nwant: % x", gotInner, wantInner)
	}
}

// TestEdgeLB_UndeliverablePacketCountsAsDrop guards the accounting half of
// the "silent black hole" this datapath shipped with: a packet the gateway
// claimed and then could not deliver must move the VIP's own
// dropped_packets, not just a global reason bucket. It previously moved
// neither -- push_outer_header's failure paths counted a reason and
// returned, leaving vip_stats_table reading as pure success while nothing
// reached a backend. The FIB lookup against a synthetic uSID with no route
// on the test host is the reachable failure path here; the accounting is
// shared by every other one.
func TestEdgeLB_UndeliverablePacketCountsAsDrop(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8::100")
	key := vipKey(ipprotoTCP, 8080, vip)

	var value EdgedsrVipValue
	value.BackendCount = 1
	value.Backends[0] = EdgedsrBackend{
		Addr: netip.MustParseAddr("fd20:60::5").As16(),
		Port: bswap16(30080),
		Usid: netip.MustParseAddr("fc00:1:2::a1b2").As16(),
	}
	if err := objs.VipTable.Put(key, value); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}
	if err := objs.EncapConfigTable.Put(uint32(0), EdgedsrEncapConfig{
		EncapSrc: netip.MustParseAddr("fc00:0:2::1").As16(),
	}); err != nil {
		t.Fatalf("populate encap_config_table: %v", err)
	}

	pkt := buildL4Packet(t, ipprotoTCP, vip, netip.MustParseAddr("2001:db8:ffff::1"), 41000, 8080, nil)
	ret, _, err := objs.EdgeLb.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}

	var stats EdgedsrVipStatsValue
	if err := objs.VipStatsTable.Lookup(key, &stats); err != nil {
		t.Fatalf("lookup vip_stats_table: %v", err)
	}
	if stats.Packets != 1 {
		t.Errorf("vip_stats.packets = %d, want 1 (the packet was claimed)", stats.Packets)
	}
	if stats.DroppedPackets != 1 {
		t.Errorf("vip_stats.dropped_packets = %d, want 1 (a claimed packet that could not be "+
			"delivered must not read as delivered)", stats.DroppedPackets)
	}
}

// TestDropReasonNamesCoverEveryReason keeps dropreason.go's hand-maintained
// mirror of the C enum honest: the metrics collector iterates 0..DropReasonCount
// and labels each index from this map, so a reason added to the datapath
// without a name here would export an empty label rather than fail loudly.
func TestDropReasonNamesCoverEveryReason(t *testing.T) {
	for i := range DropReasonCount {
		if DropReasonNames[i] == "" {
			t.Errorf("DropReasonNames is missing an entry for reason index %d", i)
		}
	}
	if len(DropReasonNames) != int(DropReasonCount) {
		t.Errorf("len(DropReasonNames) = %d, want %d (DropReasonCount)", len(DropReasonNames), DropReasonCount)
	}
}

// buildReturnPacket builds a reply the way a backend sends one under DSR: the
// VIP as its source, the off-fabric client as its destination, and no
// encapsulation, since the node that answered stripped it.
func buildReturnPacket(t *testing.T, vip, client netip.Addr, hopLimit byte) []byte {
	t.Helper()
	pkt := buildL4Packet(t, ipprotoTCP, client, vip, 80, 44450, nil)
	pkt[ethLen+7] = hopLimit
	return pkt
}

func vipAddrKey(vip netip.Addr) EdgedsrVipAddrKey {
	return EdgedsrVipAddrKey{Vip: vip.As16()}
}

// TestEdgeReturn_ForwardsReplyFromAClaimedVIP is the return path's core
// property: a reply sourced from a VIP this node holds is forwarded by this
// program rather than handed to the stack, where connection tracking would
// mark it invalid and kube-proxy's KUBE-FORWARD chain would drop it -- the
// forward half having crossed the backend's node inside an encapsulated
// packet that netfilter never saw.
//
// As in TestEdgeLB_ForwardsPacketUnmodifiedToBackend, the FIB lookup itself
// cannot succeed here (no route to the synthetic client exists on the test
// host), so reaching a FIB drop rather than XDP_PASS is the evidence that the
// packet was claimed and put on the forwarding path.
func TestEdgeReturn_ForwardsReplyFromAClaimedVIP(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8:6060::1")
	client := netip.MustParseAddr("2001:db8:1:40::2")
	if err := objs.VipAddrTable.Put(vipAddrKey(vip), EdgedsrVipAddrValue{Generation: 7}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}

	pkt := buildReturnPacket(t, vip, client, 64)
	ret, _, err := objs.EdgeReturn.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d) (the FIB lookup against a synthetic client must fail, "+
			"not succeed)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed); got != 1 {
		t.Errorf("drop_reasons[fib_lookup_failed] = %d, want 1 (the reply must reach the forwarding path)", got)
	}

	var stats EdgedsrVipStatsValue
	if err := objs.VipReturnStatsTable.Lookup(vipAddrKey(vip), &stats); err != nil {
		t.Fatalf("lookup vip_return_stats_table: %v", err)
	}
	if stats.Packets != 1 || stats.DroppedPackets != 1 {
		t.Errorf("return stats = {packets: %d, dropped: %d}, want {1, 1}", stats.Packets, stats.DroppedPackets)
	}
}

// TestEdgeReturn_PassesTrafficFromAnUnclaimedSource covers everything else
// crossing this interface -- the compute tier's ordinary egress, encapsulated
// tenant traffic, the node's own management traffic. None of it is this
// gateway's to forward, so it must reach the stack completely untouched.
func TestEdgeReturn_PassesTrafficFromAnUnclaimedSource(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8:6060::1")
	if err := objs.VipAddrTable.Put(vipAddrKey(vip), EdgedsrVipAddrValue{Generation: 7}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}

	other := netip.MustParseAddr("fd20:10:ff01::100:0")
	pkt := buildReturnPacket(t, other, netip.MustParseAddr("2001:db8:1:40::2"), 64)
	ret, out, err := objs.EdgeReturn.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet mutated on a vip_addr_table miss:\n in: % x\nout: % x", pkt, out)
	}
}

// TestEdgeReturn_DropsAnExpiredHopLimit guards the forwarding obligation this
// program takes on by handling the packet itself: the kernel never sees it, so
// nothing else expires a looping packet.
func TestEdgeReturn_DropsAnExpiredHopLimit(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vip := netip.MustParseAddr("2001:db8:6060::1")
	if err := objs.VipAddrTable.Put(vipAddrKey(vip), EdgedsrVipAddrValue{Generation: 7}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}

	pkt := buildReturnPacket(t, vip, netip.MustParseAddr("2001:db8:1:40::2"), 1)
	ret, _, err := objs.EdgeReturn.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonReturnHopLimit); got != 1 {
		t.Errorf("drop_reasons[return_hop_limit] = %d, want 1", got)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed); got != 0 {
		t.Errorf("drop_reasons[fib_lookup_failed] = %d, want 0 (an expired packet must not reach the FIB)", got)
	}
}
