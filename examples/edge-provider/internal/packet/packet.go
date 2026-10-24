// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package packet answers IPv6 packets read from a TUN device: ICMPv6 echo
// requests with echo replies, and UDP datagrams with a datagram carrying the
// responder's identity followed by the request's payload. A reply is sent
// from the request's destination, which lies in a prefix the provider
// serves.
package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	headerLen       = 40
	udpHeaderLen    = 8
	protoUDP        = 17
	protoICMPv6     = 58
	icmpEchoRequest = 128
	icmpEchoReply   = 129
	hopLimit        = 64
)

// ErrIgnored is returned for a packet the responder does not answer.
var ErrIgnored = errors.New("packet: not an echo request or UDP datagram")

// Reply returns the answer to the IPv6 packet p, or ErrIgnored. identity is
// prefixed to a UDP reply's payload, separated by a space.
func Reply(p []byte, identity string) ([]byte, error) {
	if len(p) < headerLen || p[0]>>4 != 6 {
		return nil, ErrIgnored
	}
	payloadLen := int(binary.BigEndian.Uint16(p[4:6]))
	if headerLen+payloadLen > len(p) {
		return nil, ErrIgnored
	}
	src, _ := netip.AddrFromSlice(p[8:24])
	dst, _ := netip.AddrFromSlice(p[24:40])
	if dst.IsMulticast() || !dst.IsGlobalUnicast() {
		return nil, ErrIgnored
	}
	body := p[headerLen : headerLen+payloadLen]
	switch p[6] {
	case protoICMPv6:
		if len(body) < 8 || body[0] != icmpEchoRequest || body[1] != 0 {
			return nil, ErrIgnored
		}
		out := append([]byte(nil), body...)
		out[0] = icmpEchoReply
		binary.BigEndian.PutUint16(out[2:4], 0)
		binary.BigEndian.PutUint16(out[2:4], checksum(dst, src, protoICMPv6, out))
		return packetOf(dst, src, protoICMPv6, out), nil
	case protoUDP:
		if len(body) < udpHeaderLen || int(binary.BigEndian.Uint16(body[4:6])) != len(body) {
			return nil, ErrIgnored
		}
		data := append([]byte(identity+" "), body[udpHeaderLen:]...)
		out := make([]byte, udpHeaderLen+len(data))
		copy(out[0:2], body[2:4])
		copy(out[2:4], body[0:2])
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)))
		copy(out[udpHeaderLen:], data)
		sum := checksum(dst, src, protoUDP, out)
		if sum == 0 {
			sum = 0xffff
		}
		binary.BigEndian.PutUint16(out[6:8], sum)
		return packetOf(dst, src, protoUDP, out), nil
	}
	return nil, ErrIgnored
}

func packetOf(src, dst netip.Addr, proto byte, payload []byte) []byte {
	out := make([]byte, headerLen+len(payload))
	out[0] = 6 << 4
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	out[6], out[7] = proto, hopLimit
	s, d := src.As16(), dst.As16()
	copy(out[8:24], s[:])
	copy(out[24:40], d[:])
	copy(out[headerLen:], payload)
	return out
}

// checksum is the Internet checksum of payload with the IPv6 pseudo-header.
func checksum(src, dst netip.Addr, proto byte, payload []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	s, d := src.As16(), dst.As16()
	add(s[:])
	add(d[:])
	var l [8]byte
	binary.BigEndian.PutUint32(l[0:4], uint32(len(payload)))
	l[7] = proto
	add(l[:])
	add(payload)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
