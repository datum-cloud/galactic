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

// Tests for #764: vip_xlat_table rows are keyed by address as well as port,
// and both programs look them up before NPTv6 runs.

// vipTestPort is the VIP and backend port the ingress tests bind.
const vipTestPort = 443

// setUpVIPIngress registers usid as a local End.DT46 SID for a VRF whose
// table has no routes, so usid_ingress runs through the VIP rewrite and stops
// at the FIB lookup.
func setUpVIPIngress(t *testing.T, objs *UsidObjects, usid testUSID) {
	t.Helper()
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: 0x2D2D2D}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
}

// putVIPIngressRow writes the ingress row RegisterIngress would for a UDP
// binding of vip:port to backend:port.
func putVIPIngressRow(t *testing.T, objs *UsidObjects, usid testUSID, vip, backend netip.Addr, port uint16) {
	t.Helper()
	key := UsidVipXlatKey{
		Block: usid.block, Argument: usid.argument, Proto: ipProtoUDP,
		Direction: usidVIPXlatDirIngress, Port: bswap16(port), Addr: vip.As16(),
	}
	if err := objs.VipXlatTable.Put(key, UsidVipXlatValue{Addr: backend.As16(), Port: bswap16(port)}); err != nil {
		t.Fatalf("populate vip_xlat_table ingress row for %s: %v", vip, err)
	}
}

// putNPTv6 configures the RFC 6296 section 3.6 translation for the VRF
// identified by (block, argument).
func putNPTv6(t *testing.T, objs *UsidObjects, block uint64, argument uint16) {
	t.Helper()
	vrfKey, err := uformat.NewVRFKey(block, argument)
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
}

// udpTo builds a checksummed UDP datagram from src:54321 to dst:port.
func udpTo(src, dst netip.Addr, port uint16) []byte {
	payload := []byte("hello")
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udp6Checksum(src.As16(), dst.As16(), udp))
	return udp
}

// runIngressToDaddr sends a UDP packet for dst:vipTestPort through usid_ingress
// and returns the inner destination it leaves with.
func runIngressToDaddr(t *testing.T, objs *UsidObjects, usid testUSID, dst netip.Addr) netip.Addr {
	const port = vipTestPort
	t.Helper()
	src := netip.MustParseAddr("2001:db8:ffff::1")
	pkt := buildPacketWithUDPInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), src, dst, udpTo(src, dst, port))
	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("verdict = %d, want TC_ACT_SHOT (%d) at the FIB lookup", ret, tcActShot)
	}
	const daddrOffset = ethHeaderLen + 24
	got, _ := netip.AddrFromSlice(out[daddrOffset : daddrOffset+16])
	return got
}

// TestUsidIngress_VIPXlatSelectsRowByVIPAddress: two VIPs in one VRF on the
// same port each reach their own backend.
func TestUsidIngress_VIPXlatSelectsRowByVIPAddress(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x764}
	setUpVIPIngress(t, objs, usid)

	const port = vipTestPort
	vipA, backendA := netip.MustParseAddr("2001:db8:6060::a"), netip.MustParseAddr("fd20:60::a")
	vipB, backendB := netip.MustParseAddr("2001:db8:6060::b"), netip.MustParseAddr("fd20:60::b")
	putVIPIngressRow(t, objs, usid, vipA, backendA, port)
	putVIPIngressRow(t, objs, usid, vipB, backendB, port)

	if got := runIngressToDaddr(t, objs, usid, vipA); got != backendA {
		t.Errorf("packet to %s left for %s, want %s", vipA, got, backendA)
	}
	if got := runIngressToDaddr(t, objs, usid, vipB); got != backendB {
		t.Errorf("packet to %s left for %s, want %s", vipB, got, backendB)
	}

	// An address with no binding on that port is left alone.
	other := netip.MustParseAddr("2001:db8:6060::c")
	if got := runIngressToDaddr(t, objs, usid, other); got != other {
		t.Errorf("packet to unbound %s left for %s, want it unchanged", other, got)
	}
}

// TestUsidIngress_VIPXlatRunsBeforeNPTv6: in a VRF with NPTv6, a packet to a
// VIP is rewritten to its backend rather than having its prefix translated
// first, and a packet to any other address still gets NPTv6.
func TestUsidIngress_VIPXlatRunsBeforeNPTv6(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x765}
	setUpVIPIngress(t, objs, usid)
	putNPTv6(t, objs, usid.block, usid.argument)

	const port = vipTestPort
	vip, backend := netip.MustParseAddr("2001:db8:6060::a"), netip.MustParseAddr("fd01:203:405:1::a")
	putVIPIngressRow(t, objs, usid, vip, backend, port)

	if got := runIngressToDaddr(t, objs, usid, vip); got != backend {
		t.Errorf("packet to VIP %s left for %s, want %s", vip, got, backend)
	}

	// RFC 6296 section 3.6's worked example, as in
	// TestUsidIngress_NPTv6TranslatesDestinationBeforeFIBLookup.
	public := netip.MustParseAddr("2001:db8:1:d550::1234")
	want := netip.MustParseAddr("fd01:203:405:1::1234")
	if got := runIngressToDaddr(t, objs, usid, public); got != want {
		t.Errorf("packet to %s left for %s, want %s (NPTv6)", public, got, want)
	}
}

// putVIPEgressRow writes the egress row RegisterEgress would for a TCP
// binding of vip:port to backend:port.
func putVIPEgressRow(
	t *testing.T, objs *UsidObjects, block uint64, argument uint16, backend, vip netip.Addr, port uint16,
) {
	t.Helper()
	key := UsidVipXlatKey{
		Block: block, Argument: argument, Proto: ipProtoTCP,
		Direction: usidVIPXlatDirEgress, Port: bswap16(port), Addr: backend.As16(),
	}
	if err := objs.VipXlatTable.Put(key, UsidVipXlatValue{Addr: vip.As16(), Port: bswap16(port)}); err != nil {
		t.Fatalf("populate vip_xlat_table egress row for %s: %v", backend, err)
	}
}

// runEgressFrom sends a TCP segment from src:port through usid_egress and
// returns the verdict and the source it leaves with.
func runEgressFrom(t *testing.T, objs *UsidObjects, src netip.Addr, port uint16) (uint32, netip.Addr) {
	t.Helper()
	client := netip.MustParseAddr("2001:db8:0:13::1")
	pkt := buildPlainV6PacketWithL4Ports(t, src, client, port, 43210)
	ret, out, err := objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	const saddrOffset = ethHeaderLen + 8
	got, _ := netip.AddrFromSlice(out[saddrOffset : saddrOffset+16])
	return ret, got
}

// TestUsidEgress_VIPXlatIgnoresNonBackendSource: a workload that is not a
// binding's backend keeps its own source even when it sends from the bound
// port, while the backend's reply is rewritten to the VIP.
func TestUsidEgress_VIPXlatIgnoresNonBackendSource(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	block, argument := uint64(0xFEEDFA), uint16(0x501)
	setUpEgressRouteAttachment(t, objs, block, argument, 14)
	if err := objs.PublicUplinkTable.Put(uint32(0), UsidPublicUplinkValue{LinkIfindex: 1}); err != nil {
		t.Fatalf("populate public_uplink_table: %v", err)
	}

	const port = 80
	backend := netip.MustParseAddr("fd20:60:ff03::100:0")
	vip := netip.MustParseAddr("2001:db8:6060::1")
	putVIPEgressRow(t, objs, block, argument, backend, vip, port)

	ret, src := runEgressFrom(t, objs, backend, port)
	if ret != tcActRedirect || src != vip {
		t.Errorf("backend reply: verdict=%d src=%s, want TC_ACT_REDIRECT (%d) from %s", ret, src, tcActRedirect, vip)
	}

	other := netip.MustParseAddr("fd20:60:ff03::200:0")
	ret, src = runEgressFrom(t, objs, other, port)
	if ret == tcActRedirect || src != other {
		t.Errorf("non-backend workload: verdict=%d src=%s, want no public-uplink redirect and src %s", ret, src, other)
	}
}

// TestUsidEgress_VIPXlatRunsBeforeNPTv6: in a VRF with NPTv6, the backend's
// reply matches its egress row by its own ULA source and leaves from the VIP,
// not from the NPTv6-translated address.
func TestUsidEgress_VIPXlatRunsBeforeNPTv6(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	block, argument := uint64(0xFEEDFA), uint16(0x502)
	setUpEgressRouteAttachment(t, objs, block, argument, 15)
	putNPTv6(t, objs, block, argument)
	if err := objs.PublicUplinkTable.Put(uint32(0), UsidPublicUplinkValue{LinkIfindex: 1}); err != nil {
		t.Fatalf("populate public_uplink_table: %v", err)
	}

	const port = 80
	backend := netip.MustParseAddr("fd01:203:405:1::1234")
	vip := netip.MustParseAddr("2001:db8:6060::1")
	putVIPEgressRow(t, objs, block, argument, backend, vip, port)

	ret, src := runEgressFrom(t, objs, backend, port)
	if ret != tcActRedirect || src != vip {
		t.Errorf("backend reply: verdict=%d src=%s, want TC_ACT_REDIRECT (%d) from %s", ret, src, tcActRedirect, vip)
	}

	// A different port from the same workload is ordinary tenant traffic and
	// still gets NPTv6 (RFC 6296 section 3.6's worked example).
	_, src = runEgressFrom(t, objs, backend, port+1)
	if want := netip.MustParseAddr("2001:db8:1:d550::1234"); src != want {
		t.Errorf("non-VIP traffic src = %s, want %s (NPTv6)", src, want)
	}
}
