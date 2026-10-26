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

func TestVIPRangeIngressPreservesPortsPayloadAndChecksum(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	usid := testUSID{block: baseUSID.block,
		nodeID:   baseUSID.nodeID,
		function: uformat.FunctionEndDT46,
		argument: 0x765,
		slot:     1}
	setUpVIPIngress(t, objs, usid)
	vip,
		backend,
		client := netip.MustParseAddr("2001:db8:6060::1"),
		netip.MustParseAddr("fd20:60::1"),
		netip.MustParseAddr("2001:db8:ffff::1")
	key := UsidVipXlatKey{Block: usid.block,
		Argument: usid.argument,
		Slot:     usid.slot,
		Proto:    ipProtoUDP,
		Addr:     vip.As16()}
	value := UsidVipXlatRangeValue{Count: 1}
	value.Ranges[0] = UsidVipXlatRange{Start: 10000, End: 10127, Rewrite: UsidVipXlatValue{Addr: backend.As16()}}
	if err := objs.VipXlatRangeTable.Put(key, value); err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{9999, 10000, 10064, 10127, 10128} {
		udp := udpTo(client, vip, port)
		pkt := buildPacketWithUDPInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), client, vip, udp)
		_, out, err := objs.UsidIngress.Test(pkt)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := netip.AddrFromSlice(out[ethHeaderLen+24 : ethHeaderLen+40])
		source, _ := netip.AddrFromSlice(out[ethHeaderLen+8 : ethHeaderLen+24])
		if source != client {
			t.Fatalf("client address changed: %s", source)
		}
		want := vip
		if port >= 10000 && port <= 10127 {
			want = backend
		}
		if got != want {
			t.Fatalf("port %d destination %s != %s", port, got, want)
		}
		l4 := out[ethHeaderLen+40:]
		if binary.BigEndian.Uint16(l4[2:4]) != port || binary.BigEndian.Uint16(l4[:2]) != 54321 || !bytes.Equal(l4[8:],
			udp[8:]) {
			t.Fatalf("port %d payload/socket changed", port)
		}
		checksum := binary.BigEndian.Uint16(l4[6:8])
		copyL4 := bytes.Clone(l4)
		copyL4[6], copyL4[7] = 0, 0
		if checksum != udp6Checksum(client.As16(), want.As16(), copyL4) {
			t.Fatalf("port %d checksum invalid", port)
		}
	}
}

func TestVIPRangeEgressPreservesPublicPort(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	block, argument := uint64(0xFEEDFA), uint16(0x501)
	setUpEgressRouteAttachment(t, objs, block, argument, 14)
	if err := objs.PublicUplinkTable.Put(uint32(0), UsidPublicUplinkValue{LinkIfindex: 1}); err != nil {
		t.Fatal(err)
	}
	backend,
		vip,
		client := netip.MustParseAddr("fd20:60:ff03::100:0"),
		netip.MustParseAddr("2001:db8:6060::1"),
		netip.MustParseAddr("2001:db8:0:13::1")
	key := UsidVipXlatKey{Block: block,
		Argument:  argument,
		Proto:     ipProtoUDP,
		Direction: usidVIPXlatDirEgress,
		Addr:      backend.As16()}
	value := UsidVipXlatRangeValue{Count: 1}
	value.Ranges[0] = UsidVipXlatRange{Start: 10000, End: 10127, Rewrite: UsidVipXlatValue{Addr: vip.As16()}}
	if err := objs.VipXlatRangeTable.Put(key, value); err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{10000, 10064, 10127} {
		base := buildPlainV6PacketWithL4Ports(t, backend, client, port, 43210)
		udp := udpTo(backend, client, 43210)
		binary.BigEndian.PutUint16(udp[:2], port)
		udp[6], udp[7] = 0, 0
		binary.BigEndian.PutUint16(udp[6:8], udp6Checksum(backend.As16(), client.As16(), udp))
		pkt := append(base[:ethHeaderLen+40], udp...)
		pkt[ethHeaderLen+6] = ipProtoUDP
		binary.BigEndian.PutUint16(pkt[ethHeaderLen+4:ethHeaderLen+6], uint16(len(udp)))
		ret, out, err := objs.UsidEgress.Test(pkt)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := netip.AddrFromSlice(out[ethHeaderLen+8 : ethHeaderLen+24])
		if ret != tcActRedirect || got != vip {
			t.Fatalf("port %d return verdict=%d source=%s", port, ret, got)
		}
		l4 := out[ethHeaderLen+40:]
		destination, _ := netip.AddrFromSlice(out[ethHeaderLen+24 : ethHeaderLen+40])
		if destination != client {
			t.Fatalf("return destination changed: %s", destination)
		}
		if binary.BigEndian.Uint16(l4[:2]) != port || binary.BigEndian.Uint16(l4[2:4]) != 43210 || !bytes.Equal(l4[8:],
			udp[8:]) {
			t.Fatal("return source port changed")
		}
		checksum := binary.BigEndian.Uint16(l4[6:8])
		l4 = bytes.Clone(l4)
		l4[6], l4[7] = 0, 0
		if checksum != udp6Checksum(vip.As16(), client.As16(), l4) {
			t.Fatal("return checksum invalid")
		}
	}
}
