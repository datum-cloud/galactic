// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
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

// buildUDPPacket constructs a minimal Ethernet+IPv6+UDP frame -- vip_table
// only ever matches TCP/UDP traffic, and UDP's fixed 8-byte header is the
// simplest well-formed L4 payload to synthesize.
func buildUDPPacket(t *testing.T, dst, src netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()

	pkt := make([]byte, 0, ethLen+ip6Len+udpLen+len(payload))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x86, 0xDD)

	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	udpTotalLen := uint16(udpLen + len(payload))
	pkt = append(pkt, byte(udpTotalLen>>8), byte(udpTotalLen))
	pkt = append(pkt, ipprotoUDP)
	pkt = append(pkt, 64)
	srcBytes := src.As16()
	pkt = append(pkt, srcBytes[:]...)
	dstBytes := dst.As16()
	pkt = append(pkt, dstBytes[:]...)

	pkt = append(pkt, byte(srcPort>>8), byte(srcPort))
	pkt = append(pkt, byte(dstPort>>8), byte(dstPort))
	pkt = append(pkt, byte(udpTotalLen>>8), byte(udpTotalLen))
	pkt = append(pkt, 0x00, 0x00) // checksum, unchecked/untouched by this program
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

	pkt := buildUDPPacket(t, vip, netip.MustParseAddr("2001:db8:ffff::1"), 5000, 443, []byte("hi"))
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

	pkt := buildUDPPacket(t, vip, netip.MustParseAddr("2001:db8:ffff::1"), 5000, 443, []byte("hi"))
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
	pkt := buildUDPPacket(t, vip, client, 5000, 443, payload)

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

	const innerOffset = ethLen + ip6Len
	gotInner := out[innerOffset:]
	wantInner := pkt[ethLen:] // the original packet's own IPv6 header onward, byte-for-byte
	if string(gotInner) != string(wantInner) {
		t.Errorf("inner packet was modified -- DSR must forward the client's packet completely "+
			"untouched:\n got: % x\nwant: % x", gotInner, wantInner)
	}
}
