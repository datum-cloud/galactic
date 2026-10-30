// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// hostOnlyTestIfindex is the loopback device's ifindex, the device a
// BPF_PROG_TEST_RUN without a context runs the program against.
const hostOnlyTestIfindex = 1

// hostOnlyFrame6 builds an Ethernet frame carrying an IPv6 packet to dst whose
// header names next, followed by the extension headers in ext (each 8 bytes,
// naming the one after it) and a TCP header to dport.
func hostOnlyFrame6(dst netip.Addr, dport uint16, next byte, ext ...[]byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 5 << 4

	var chain []byte
	for _, e := range ext {
		chain = append(chain, e...)
	}
	payload := append(chain, tcp...)

	frame := []byte{0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x86, 0xdd}
	ip6 := make([]byte, 40)
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:], uint16(len(payload)))
	ip6[6] = next
	ip6[7] = 64
	src := netip.MustParseAddr("2001:db8::2").As16()
	copy(ip6[8:], src[:])
	d := dst.As16()
	copy(ip6[24:], d[:])
	frame = append(frame, ip6...)
	return append(frame, payload...)
}

func hostOnlyFrame4(dport uint16, fragOffset uint16) []byte {
	frame := []byte{0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00}
	ip4 := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, usidIPProtoTCP, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1}
	binary.BigEndian.PutUint16(ip4[6:], fragOffset)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	frame = append(frame, ip4...)
	return append(frame, tcp...)
}

// extHeader returns an 8-byte IPv6 extension header naming next.
func extHeader(next byte) []byte {
	return []byte{next, 0, 0, 0, 0, 0, 0, 0}
}

// fragHeader returns an IPv6 Fragment header naming next at offset (in
// 8-byte units).
func fragHeader(next byte, offset uint16) []byte {
	h := []byte{next, 0, 0, 0, 0, 0, 0, 1}
	binary.BigEndian.PutUint16(h[2:], offset<<3)
	return h
}

const (
	usidIPProtoTCP        = 6
	usidIPProtoDstOpts    = 60
	usidIPProtoFragment   = 44
	usidIPProtoAH         = 51
	hostOnlyProtectedPort = 20000
)

// TestTpDeliver_HostOnlyPorts checks tp_deliver refuses TCP for a host-only
// port unless the packet is addressed to the guest's link-local address, and
// leaves every other packet, and every attachment without an entry, alone.
func TestTpDeliver_HostOnlyPorts(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	vpcAddr := netip.MustParseAddr("2001:db8::1")
	linkLocal := netip.MustParseAddr("fe80::1")

	cases := []struct {
		name  string
		frame []byte
		want  uint32
	}{
		{"VPC address, host-only port", hostOnlyFrame6(vpcAddr, hostOnlyProtectedPort, usidIPProtoTCP), tcActShot},
		{"VPC address, other port", hostOnlyFrame6(vpcAddr, 6379, usidIPProtoTCP), tcActUnspec},
		{"link-local address, host-only port",
			hostOnlyFrame6(linkLocal, hostOnlyProtectedPort, usidIPProtoTCP), tcActUnspec},
		{"behind a destination options header", hostOnlyFrame6(vpcAddr, hostOnlyProtectedPort,
			usidIPProtoDstOpts, extHeader(usidIPProtoTCP)), tcActShot},
		{"first fragment", hostOnlyFrame6(vpcAddr, hostOnlyProtectedPort,
			usidIPProtoFragment, fragHeader(usidIPProtoTCP, 0)), tcActShot},
		{"non-first fragment", hostOnlyFrame6(vpcAddr, hostOnlyProtectedPort,
			usidIPProtoFragment, fragHeader(usidIPProtoTCP, 2)), tcActUnspec},
		{"header chain it cannot follow", hostOnlyFrame6(vpcAddr, 6379,
			usidIPProtoAH, extHeader(usidIPProtoTCP)), tcActShot},
		{"IPv4, host-only port", hostOnlyFrame4(hostOnlyProtectedPort, 0), tcActShot},
		{"IPv4, non-first fragment", hostOnlyFrame4(hostOnlyProtectedPort, 3), tcActUnspec},
	}

	run := func(t *testing.T, frame []byte) uint32 {
		t.Helper()
		ret, _, err := objs.TpDeliver.Test(frame)
		if err != nil {
			t.Fatalf("run tp_deliver: %v", err)
		}
		return ret
	}

	for _, tc := range cases {
		if got := run(t, tc.frame); got != tcActUnspec {
			t.Errorf("%s, no entry: got %d, want %d", tc.name, got, tcActUnspec)
		}
	}

	entry := UsidHostOnlyPortsValue{Tcp: [4]uint16{hostOnlyProtectedPort}}
	if err := objs.HostOnlyPortTable.Put(uint32(hostOnlyTestIfindex), entry); err != nil {
		t.Fatalf("write host_only_port_table: %v", err)
	}
	var shot uint64
	for _, tc := range cases {
		if got := run(t, tc.frame); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
		if tc.want == tcActShot {
			shot++
		}
	}

	var per []uint64
	if err := objs.HostOnlyPortDrops.Lookup(uint32(0), &per); err != nil {
		t.Fatalf("read host_only_port_drops: %v", err)
	}
	var drops uint64
	for _, n := range per {
		drops += n
	}
	if drops != shot {
		t.Errorf("host_only_port_drops = %d, want %d", drops, shot)
	}
}
