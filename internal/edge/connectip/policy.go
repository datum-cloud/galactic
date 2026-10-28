// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"encoding/binary"
	"net/netip"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"
)

const (
	// maxExtensionHeaders and maxExtensionBytes bound the IPv6 extension
	// header chain the policy walks to reach the upper-layer header.
	maxExtensionHeaders = 8
	maxExtensionBytes   = 256

	ipv6HeaderLen = 40

	protoHopByHop    = 0
	protoRouting     = 43
	protoFragment    = 44
	protoAuth        = 51
	protoICMPv6      = 58
	protoDestOptions = 60
)

// Directions, the direction label of packetsDenied.
const (
	toVPC    = "to_vpc"
	toClient = "to_client"
)

// Reasons a packet is refused, the reason label of packetsDenied.
const (
	// reasonMalformed is a packet whose lengths or header order are wrong.
	reasonMalformed = "malformed"
	// reasonIPv4 is an IPv4 packet; only IPv6 is carried.
	reasonIPv4 = "ipv4_unsupported"
	// reasonFragment is any packet with a Fragment header, atomic ones too.
	reasonFragment = "fragment"
	// reasonExtensionHeaders is a chain longer than the policy walks, or an
	// extension header it cannot evaluate.
	reasonExtensionHeaders = "extension_headers"
	// reasonRoutingHeader is a Routing header with segments left: the
	// packet's destination address is only its next hop, so the policy
	// cannot evaluate where it goes.
	reasonRoutingHeader = "routing_header"
	// reasonSource is a source the session does not own or route.
	reasonSource = "source"
	// reasonDestination is a destination the session does not own or route.
	reasonDestination = "destination"
	// reasonNoSession is a packet from the device for a /96 with no open
	// session.
	reasonNoSession = "no_session"
)

var packetsDenied = metrics.NewCounterVec(prometheus.CounterOpts{
	Name: "galactic_connectip_packets_denied_total",
	Help: "Packets the CONNECT-IP proxy refused to forward under the session packet policy, by direction and " +
		"reason.",
}, []string{"direction", labels.Reason})

func deny(direction, reason string) {
	packetsDenied.WithLabelValues(direction, reason).Inc()
}

// packetPolicy is one session's packet policy. A packet toward the gVPC
// must come from the connector's /96 and go to an advertised route; a
// packet toward the client must go to the /96 and come from a route, or be
// an ICMPv6 error about a packet the client sent to a route.
type packetPolicy struct {
	prefix netip.Prefix
	routes []netip.Prefix
}

func newPacketPolicy(prefix netip.Prefix, routes []netip.Prefix) *packetPolicy {
	masked := make([]netip.Prefix, len(routes))
	for i, r := range routes {
		masked[i] = r.Masked()
	}
	return &packetPolicy{prefix: prefix, routes: masked}
}

func (p *packetPolicy) routed(a netip.Addr) bool {
	return slices.ContainsFunc(p.routes, func(r netip.Prefix) bool { return r.Contains(a) })
}

// fromClient returns why a packet from the client may not enter the gVPC,
// or "" when it may. An ICMPv6 error is held to the same source check: the
// client sends its errors from its own addresses.
func (p *packetPolicy) fromClient(pkt []byte) string {
	h, reason := parsePacket(pkt)
	switch {
	case reason != "":
		return reason
	case !p.prefix.Contains(h.src):
		return reasonSource
	case !p.routed(h.dst):
		return reasonDestination
	}
	return ""
}

// toClient returns why a packet from the gVPC may not reach the client, or
// "" when it may. A router on the path may send an ICMPv6 error (types 1 to
// 4) from an address outside the routes, so such an error passes when the
// packet it quotes went from the client's address to a route.
func (p *packetPolicy) toClient(pkt []byte) string {
	h, reason := parsePacket(pkt)
	switch {
	case reason != "":
		return reason
	case !p.prefix.Contains(h.dst):
		return reasonDestination
	case p.routed(h.src):
		return ""
	case h.proto != protoICMPv6 || h.upper[0] < 1 || h.upper[0] > 4:
		// Only Destination Unreachable, Packet Too Big, Time Exceeded and
		// Parameter Problem quote the packet that caused them.
		return reasonSource
	}
	// The quoted packet is usually truncated, so only its fixed header is
	// read.
	quoted := h.upper[8:]
	if len(quoted) < ipv6HeaderLen || quoted[0]>>4 != 6 {
		return reasonMalformed
	}
	src := netip.AddrFrom16([16]byte(quoted[8:24]))
	dst := netip.AddrFrom16([16]byte(quoted[24:40]))
	if src != h.dst || !p.routed(dst) {
		return reasonSource
	}
	return ""
}

// packetHeader is what the policy reads from a packet.
type packetHeader struct {
	src, dst netip.Addr
	// proto is the upper-layer protocol and upper its header and payload.
	proto uint8
	upper []byte
}

// parsePacket parses a complete IPv6 packet and walks its extension
// headers to the upper layer. It returns the reason the packet cannot be
// evaluated, or "".
func parsePacket(pkt []byte) (packetHeader, string) {
	if len(pkt) == 0 {
		return packetHeader{}, reasonMalformed
	}
	switch pkt[0] >> 4 {
	case 6:
	case 4:
		return packetHeader{}, reasonIPv4
	default:
		return packetHeader{}, reasonMalformed
	}
	// The payload length must cover the packet exactly, which also refuses
	// jumbograms, whose payload length is zero.
	if len(pkt) < ipv6HeaderLen || int(binary.BigEndian.Uint16(pkt[4:6])) != len(pkt)-ipv6HeaderLen {
		return packetHeader{}, reasonMalformed
	}
	h := packetHeader{src: netip.AddrFrom16([16]byte(pkt[8:24])), dst: netip.AddrFrom16([16]byte(pkt[24:40]))}
	next, off, count, size := pkt[6], ipv6HeaderLen, 0, 0
	for {
		var n int
		switch next {
		case protoHopByHop, protoRouting, protoDestOptions, protoAuth:
			if next == protoHopByHop && count > 0 {
				return packetHeader{}, reasonMalformed
			}
			if len(pkt)-off < 8 {
				return packetHeader{}, reasonMalformed
			}
			if next == protoAuth {
				n = (int(pkt[off+1]) + 2) * 4
			} else {
				n = (int(pkt[off+1]) + 1) * 8
			}
		case protoFragment:
			return packetHeader{}, reasonFragment
		case 135, 139, 140, 253, 254:
			// Mobility, HIP, Shim6 and experimental headers.
			return packetHeader{}, reasonExtensionHeaders
		default:
			h.proto, h.upper = next, pkt[off:]
			// An ICMPv6 message needs its type, code and checksum, and an
			// error its 4-byte field before the quoted packet.
			if next == protoICMPv6 && (len(h.upper) < 4 || h.upper[0] < 128 && len(h.upper) < 8) {
				return packetHeader{}, reasonMalformed
			}
			return h, ""
		}
		count++
		size += n
		if count > maxExtensionHeaders || size > maxExtensionBytes {
			return packetHeader{}, reasonExtensionHeaders
		}
		if off+n > len(pkt) {
			return packetHeader{}, reasonMalformed
		}
		if next == protoRouting && pkt[off+3] != 0 {
			return packetHeader{}, reasonRoutingHeader
		}
		next, off = pkt[off], off+n
	}
}
