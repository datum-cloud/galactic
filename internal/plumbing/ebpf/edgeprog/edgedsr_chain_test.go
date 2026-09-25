// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// chainStubVerdict is what the stub chained program returns. XDP_TX, because
// neither test path below can produce it from the gateway's own programs: a
// claimed packet there is a counted drop, so a TX verdict can only have come
// from the stub.
const chainStubVerdict = xdpTx

// installChainStub loads a one-instruction XDP program returning
// chainStubVerdict and puts it in xdp_chain's slot, standing in for the egress
// translation shard that fills it in production.
//
// AttachType must be AttachXDP, as an ELF SEC("xdp") program's is: the kernel
// refuses a program into a prog array whose owner's expected attach type
// differs, with a bare EINVAL.
func installChainStub(t *testing.T, objs *EdgedsrObjects) {
	t.Helper()
	stub, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.XDP,
		AttachType: ebpf.AttachXDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, chainStubVerdict),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatalf("load chain stub program: %v", err)
	}
	t.Cleanup(func() { _ = stub.Close() })
	if err := objs.XdpChain.Put(uint32(0), stub); err != nil {
		t.Fatalf("install chain stub in xdp_chain: %v", err)
	}
}

// buildIPv4Frame is a minimal Ethernet+IPv4 frame. Neither gateway program
// parses IPv4, and a NAT64 reply arriving on the public uplink is exactly this
// shape, so the chained program must still see it.
func buildIPv4Frame() []byte {
	pkt := []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0x08, 0x00,
	}
	pkt = append(pkt, 0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, ipprotoUDP, 0, 0,
		192, 0, 2, 1, 10, 1, 40, 2)
	return append(pkt, 0x13, 0x88, 0x01, 0xbb, 0x00, 0x08, 0x00, 0x00)
}

// TestEdgeLB_ChainsUnclaimedTraffic proves that every packet edge_lb does not
// claim reaches the chained program -- a miss in vip_table and a frame that is
// not IPv6 at all -- and that a claimed one never does.
func TestEdgeLB_ChainsUnclaimedTraffic(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	installChainStub(t, objs)

	vip := netip.MustParseAddr("2001:db8::100")
	client := netip.MustParseAddr("2001:db8:ffff::1")
	if err := objs.VipTable.Put(vipKey(ipprotoUDP, 443, vip), EdgedsrVipValue{BackendCount: 0}); err != nil {
		t.Fatalf("populate vip_table: %v", err)
	}

	tests := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"vip_table miss is chained",
			buildL4Packet(t, ipprotoUDP, netip.MustParseAddr("2001:db8::200"), client, 5000, 443, nil),
			chainStubVerdict},
		{"IPv4 frame is chained", buildIPv4Frame(), chainStubVerdict},
		{"claimed VIP is not chained",
			buildL4Packet(t, ipprotoUDP, vip, client, 5000, 443, nil), xdpDrop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.EdgeLb.Test(tt.pkt)
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			if ret != tt.want {
				t.Errorf("verdict = %d, want %d", ret, tt.want)
			}
		})
	}
}

// TestEdgeReturn_ChainsUnclaimedTraffic is edge_return's counterpart: an
// encapsulated tenant packet from the compute tier, sourced from no VIP, is
// the egress shard's forward path and must reach it.
func TestEdgeReturn_ChainsUnclaimedTraffic(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	installChainStub(t, objs)

	vip := netip.MustParseAddr("2001:db8:6060::1")
	client := netip.MustParseAddr("2001:db8:1:40::2")
	if err := objs.VipAddrTable.Put(vipAddrKey(vip), EdgedsrVipAddrValue{Generation: 7}); err != nil {
		t.Fatalf("populate vip_addr_table: %v", err)
	}

	tests := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"unclaimed source is chained",
			buildReturnPacket(t, netip.MustParseAddr("fd20:10:ff01::100:0"), client, 64), chainStubVerdict},
		{"IPv4 frame is chained", buildIPv4Frame(), chainStubVerdict},
		// Hop limit 1 makes a claimed reply a counted drop, so the verdict
		// is the gateway's own and never the stub's.
		{"claimed VIP source is not chained", buildReturnPacket(t, vip, client, 1), xdpDrop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _, err := objs.EdgeReturn.Test(tt.pkt)
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			if ret != tt.want {
				t.Errorf("verdict = %d, want %d", ret, tt.want)
			}
		})
	}
}
