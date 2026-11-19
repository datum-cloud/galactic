// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// Frame helpers for the root tests: a TAP guest builds and parses Ethernet
// frames itself, as a hypervisor's guest does.

const (
	ethHdrLen   = 14
	ip6HdrLen   = 40
	udpHdrLen   = 8
	vnetHdrLen  = 10
	protoUDP    = 17
	protoICMPv6 = 58
	icmpNS      = 135
	icmpNA      = 136
	// vnetNeedsCsum is VIRTIO_NET_HDR_F_NEEDS_CSUM.
	vnetNeedsCsum = 1
)

// udpFrame is one parsed UDP-over-IPv6 frame.
type udpFrame struct {
	src, dst         netip.Addr
	sport, dport     uint16
	payload          []byte
	srcMAC, dstMAC   net.HardwareAddr
	checksumVerified bool
}

func sum16(b []byte, s uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}

// pseudo sums the IPv6 pseudo-header.
func pseudo(src, dst netip.Addr, proto uint8, l4len int) uint32 {
	s16, d16 := src.As16(), dst.As16()
	s := sum16(s16[:], 0)
	s = sum16(d16[:], s)
	s += uint32(l4len)
	s += uint32(proto)
	return s
}

// buildIP6 returns an Ethernet frame carrying an IPv6 packet with l4.
func buildIP6(srcMAC, dstMAC net.HardwareAddr, src, dst netip.Addr, proto uint8, hlim uint8, l4 []byte) []byte {
	f := make([]byte, ethHdrLen+ip6HdrLen+len(l4))
	copy(f[0:6], dstMAC)
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:], 0x86DD)
	ip := f[ethHdrLen:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
	ip[6] = proto
	ip[7] = hlim
	s16, d16 := src.As16(), dst.As16()
	copy(ip[8:24], s16[:])
	copy(ip[24:40], d16[:])
	copy(ip[40:], l4)
	return f
}

// udp returns a UDP frame. partial leaves the checksum to be finished, as a
// guest with checksum offload hands it over: the field holds the folded
// pseudo-header sum, not its complement.
func udp(srcMAC, dstMAC net.HardwareAddr, src, dst netip.Addr, sport, dport uint16, payload []byte,
	partial bool) []byte {
	l4 := make([]byte, udpHdrLen+len(payload))
	binary.BigEndian.PutUint16(l4[0:], sport)
	binary.BigEndian.PutUint16(l4[2:], dport)
	binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
	copy(l4[8:], payload)
	ps := pseudo(src, dst, protoUDP, len(l4))
	if partial {
		binary.BigEndian.PutUint16(l4[6:], fold(ps))
	} else {
		c := ^fold(sum16(l4, ps))
		if c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(l4[6:], c)
	}
	return buildIP6(srcMAC, dstMAC, src, dst, protoUDP, 64, l4)
}

// vnet prepends a virtio_net_hdr to frame; partial asks the host to finish
// the UDP checksum.
func vnet(frame []byte, partial bool) []byte {
	h := make([]byte, vnetHdrLen, vnetHdrLen+len(frame))
	if partial {
		h[0] = vnetNeedsCsum
		binary.LittleEndian.PutUint16(h[6:], ethHdrLen+ip6HdrLen) // csum_start
		binary.LittleEndian.PutUint16(h[8:], 6)                   // csum_offset
	}
	return append(h, frame...)
}

// parseUDP parses a UDP-over-IPv6 frame, verifying its checksum.
func parseUDP(f []byte) (udpFrame, bool) {
	if len(f) < ethHdrLen+ip6HdrLen+udpHdrLen || binary.BigEndian.Uint16(f[12:]) != 0x86DD {
		return udpFrame{}, false
	}
	ip := f[ethHdrLen:]
	if ip[6] != protoUDP {
		return udpFrame{}, false
	}
	plen := int(binary.BigEndian.Uint16(ip[4:]))
	if len(ip) < ip6HdrLen+plen || plen < udpHdrLen {
		return udpFrame{}, false
	}
	l4 := ip[ip6HdrLen : ip6HdrLen+plen]
	src := netip.AddrFrom16([16]byte(ip[8:24]))
	dst := netip.AddrFrom16([16]byte(ip[24:40]))
	return udpFrame{
		src: src, dst: dst,
		sport: binary.BigEndian.Uint16(l4[0:]), dport: binary.BigEndian.Uint16(l4[2:]),
		payload: append([]byte(nil), l4[8:]...),
		srcMAC:  append(net.HardwareAddr(nil), f[6:12]...), dstMAC: append(net.HardwareAddr(nil), f[0:6]...),
		checksumVerified: fold(sum16(l4, pseudo(src, dst, protoUDP, len(l4)))) == 0xffff,
	}, true
}

// neighborSolicitation returns the target and the solicitor's address and
// MAC of an ICMPv6 Neighbor Solicitation frame.
func neighborSolicitation(f []byte) (target, from netip.Addr, mac net.HardwareAddr, ok bool) {
	if len(f) < ethHdrLen+ip6HdrLen+24 || binary.BigEndian.Uint16(f[12:]) != 0x86DD {
		return netip.Addr{}, netip.Addr{}, nil, false
	}
	ip := f[ethHdrLen:]
	if ip[6] != protoICMPv6 || ip[ip6HdrLen] != icmpNS {
		return netip.Addr{}, netip.Addr{}, nil, false
	}
	return netip.AddrFrom16([16]byte(ip[ip6HdrLen+8 : ip6HdrLen+24])), netip.AddrFrom16([16]byte(ip[8:24])),
		append(net.HardwareAddr(nil), f[6:12]...), true
}

// neighborAdvertisement answers a solicitation for target from mac.
func neighborAdvertisement(mac net.HardwareAddr, target, to netip.Addr, toMAC net.HardwareAddr) []byte {
	l4 := make([]byte, 32)
	l4[0] = icmpNA
	l4[4] = 0x60 // solicited, override
	t16 := target.As16()
	copy(l4[8:24], t16[:])
	l4[24] = 2 // target link-layer address
	l4[25] = 1
	copy(l4[26:32], mac)
	if !to.IsValid() || to.IsUnspecified() {
		to = netip.MustParseAddr("ff02::1")
		toMAC = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 1}
	}
	binary.BigEndian.PutUint16(l4[2:], ^fold(sum16(l4, pseudo(target, to, protoICMPv6, len(l4)))))
	return buildIP6(mac, toMAC, target, to, protoICMPv6, 255, l4)
}
