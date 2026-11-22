// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
)

// localMetaMagicV2 and localMetaLen mirror localprog/local_meta.h's GLM2.
const (
	localMetaMagicV2 = 0x474c4d32
	localMetaLen     = 24
)

// testLocalSID is a backend uSID on this node: End.DT46 (0xE), argument
// 0x1a5, backend slot 7.
var testLocalSID = netip.MustParseAddr("fc00:1:2:3:e1a5:7::")

// xdpMd is struct xdp_md, the context BPF_PROG_TEST_RUN takes and returns.
type xdpMd struct {
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}

// runLBWithMeta runs edge_lb and returns its verdict, the metadata it left in
// front of the packet, and the packet.
func runLBWithMeta(t *testing.T, objs *EdgedsrObjects, pkt []byte) (uint32, []byte, []byte) {
	t.Helper()
	out := make([]byte, len(pkt)+256)
	var ctxOut xdpMd
	ret, err := objs.EdgeLb.Run(&ebpf.RunOptions{
		Data:       pkt,
		DataOut:    out,
		Context:    xdpMd{DataEnd: uint32(len(pkt))}, //nolint:gosec // a test frame
		ContextOut: &ctxOut,
	})
	if err != nil {
		t.Fatalf("edge_lb test-run: %v", err)
	}
	// The kernel copies the frame out from data_meta; ctx_out.data is the
	// metadata's length and ctx_out.data_end the frame's end.
	if ctxOut.Data > ctxOut.DataEnd || int(ctxOut.DataEnd) > len(out) {
		t.Fatalf("test-run context out of range: %+v", ctxOut)
	}
	return ret, out[:ctxOut.Data], out[ctxOut.Data:ctxOut.DataEnd]
}

func putLocal(t *testing.T, objs *EdgedsrObjects, sid netip.Addr, tap uint32) {
	t.Helper()
	if err := objs.EdgeLocalTable.Put(EdgedsrEdgeLocalKey{Usid: sid.As16()},
		EdgedsrEdgeLocalValue{TapIfindex: tap, Generation: 1}); err != nil {
		t.Fatalf("populate edge_local_table: %v", err)
	}
}

func localHandoffs(t *testing.T, objs *EdgedsrObjects) uint64 {
	t.Helper()
	return sumPerCPU(t, objs.LocalHandoffs, 0)
}

type localCase struct {
	name  string
	proto uint8
	vip   netip.Addr
	pkt   func(t *testing.T, proto uint8, vip netip.Addr) []byte
}

func localCases() []localCase {
	v6 := func(t *testing.T, proto uint8, vip netip.Addr) []byte {
		return buildL4Packet(t, proto, vip, netip.MustParseAddr("2001:db8:ffff::1"), 41000, 443, []byte("hello"))
	}
	v4 := func(t *testing.T, proto uint8, vip netip.Addr) []byte {
		return buildIPv4Packet(t, proto, vip, testClient4, 41000, 443, []byte("hello"), ip4Opts{fragOff: ipDF})
	}
	return []localCase{
		{"ipv6/tcp", ipprotoTCP, netip.MustParseAddr("2001:db8::100"), v6},
		{"ipv6/udp", ipprotoUDP, netip.MustParseAddr("2001:db8::100"), v6},
		{"ipv4/tcp", ipprotoTCP, testVIP4, v4},
		{"ipv4/udp", ipprotoUDP, testVIP4, v4},
	}
}

// TestEdgeLB_LocalBackendIsHandedToWorker covers a backend this node serves
// through Worker's Local local.tap handoff: the packet is passed to the kernel
// unchanged, behind GLM2 metadata naming the backend's TAP and uSID, and
// counted as a handoff rather than a drop.
func TestEdgeLB_LocalBackendIsHandedToWorker(t *testing.T) {
	for _, tc := range localCases() {
		t.Run(tc.name, func(t *testing.T) {
			requireRoot(t)
			objs := loadObjects(t)
			key := putIPv4VIP(t, objs, tc.proto, 443, tc.vip, testLocalSID)
			putLocal(t, objs, testLocalSID, 42)

			pkt := tc.pkt(t, tc.proto, tc.vip)
			ret, meta, out := runLBWithMeta(t, objs, pkt)
			if ret != xdpPass {
				t.Fatalf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
			}
			if len(meta) != localMetaLen {
				t.Fatalf("metadata is %d bytes, want %d", len(meta), localMetaLen)
			}
			if got := binary.NativeEndian.Uint32(meta[0:4]); got != localMetaMagicV2 {
				t.Errorf("metadata magic = %#x, want GLM2 %#x", got, localMetaMagicV2)
			}
			if got := binary.NativeEndian.Uint32(meta[4:8]); got != 42 {
				t.Errorf("metadata tap_ifindex = %d, want 42", got)
			}
			if got := netip.AddrFrom16([16]byte(meta[8:24])); got != testLocalSID {
				t.Errorf("metadata backend_sid = %v, want %v", got, testLocalSID)
			}
			if string(out) != string(pkt) {
				t.Errorf("packet was modified:\n got % x\nwant % x", out, pkt)
			}
			if got := localHandoffs(t, objs); got != 1 {
				t.Errorf("local_handoffs = %d, want 1", got)
			}
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

// TestEdgeLB_LocalBackendNotReadyIsDropped covers a Local backend whose
// handoff is not Ready (TAP 0): a counted drop, never encapsulated, since a
// Local backend has no fabric path.
func TestEdgeLB_LocalBackendNotReadyIsDropped(t *testing.T) {
	for _, tc := range localCases() {
		t.Run(tc.name, func(t *testing.T) {
			requireRoot(t)
			objs := loadObjects(t)
			key := putIPv4VIP(t, objs, tc.proto, 443, tc.vip, testLocalSID)
			putLocal(t, objs, testLocalSID, 0)

			ret, meta, _ := runLBWithMeta(t, objs, tc.pkt(t, tc.proto, tc.vip))
			if ret != xdpDrop {
				t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
			}
			if len(meta) != 0 {
				t.Errorf("a dropped packet carries %d bytes of metadata", len(meta))
			}
			if got := sumPerCPU(t, objs.DropReasons, DropReasonLocalUnavailable); got != 1 {
				t.Errorf("drop_reasons[local_unavailable] = %d, want 1", got)
			}
			if got := localHandoffs(t, objs); got != 0 {
				t.Errorf("local_handoffs = %d, want 0", got)
			}
			var stats EdgedsrVipStatsValue
			if err := objs.VipStatsTable.Lookup(key, &stats); err != nil {
				t.Fatalf("lookup vip_stats_table: %v", err)
			}
			if stats.Packets != 1 || stats.DroppedPackets != 1 {
				t.Errorf("vip_stats packets/dropped = %d/%d, want 1/1", stats.Packets, stats.DroppedPackets)
			}
		})
	}
}

// TestEdgeLB_RemoteBackendStillEncapsulated covers a backend with no
// edge_local_table row while another backend has one: it is encapsulated as
// before, with no metadata and no handoff counted.
func TestEdgeLB_RemoteBackendStillEncapsulated(t *testing.T) {
	for _, tc := range localCases() {
		t.Run(tc.name, func(t *testing.T) {
			requireRoot(t)
			narrowFabric4(t, []netip.Addr{testUSID})
			objs := loadObjects(t)
			putIPv4VIP(t, objs, tc.proto, 443, tc.vip, testUSID)
			putLocal(t, objs, testLocalSID, 42)

			pkt := tc.pkt(t, tc.proto, tc.vip)
			ret, meta, out := runLBWithMeta(t, objs, pkt)
			if ret != xdpRedirect {
				t.Fatalf("verdict = %d, want XDP_REDIRECT (%d)", ret, xdpRedirect)
			}
			if len(meta) != 0 {
				t.Errorf("an encapsulated packet carries %d bytes of metadata", len(meta))
			}
			if tc.vip.Is4() {
				assertIPv4Encapsulated(t, pkt, out, testUSID)
			} else {
				if len(out) != len(pkt)+ip6Len {
					t.Fatalf("output is %d bytes, want %d", len(out), len(pkt)+ip6Len)
				}
				if got := addrAt(out[ethLen:], 24); got != testUSID {
					t.Errorf("outer destination = %v, want %v", got, testUSID)
				}
				if string(out[ethLen+ip6Len:]) != string(pkt[ethLen:]) {
					t.Error("inner packet was modified")
				}
			}
			if got := localHandoffs(t, objs); got != 0 {
				t.Errorf("local_handoffs = %d, want 0", got)
			}
		})
	}
}
