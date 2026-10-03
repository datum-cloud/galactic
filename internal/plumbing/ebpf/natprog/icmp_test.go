// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

const (
	ipprotoTCP    = 6
	ipprotoICMPv6 = 58

	icmpLen = 8

	icmpv6DestUnreach   = 1
	icmpv6PacketTooBig  = 2
	icmpv6TimeExceeded  = 3
	icmpv6ParamProblem  = 4
	icmpv6EchoRequest   = 128
	icmpv6EchoReply     = 129
	icmpv6NeighborSolic = 135

	// fixtureEchoID is the Echo Identifier every tenant ping in this file
	// sends. Arbitrary, but outside the masquerade range, so a test that sees
	// it on the wire after translation knows it was not rewritten.
	fixtureEchoID = 0x1234
)

// icmp6Checksum is an independent reference implementation of the ICMPv6
// checksum (RFC 4443 section 2.3): the IPv6 pseudo-header with next header 58,
// then the message. Used only to build and verify fixtures.
func icmp6Checksum(src, dst [16]byte, msg []byte) uint16 {
	var sum uint32
	add16 := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add16(src[:])
	add16(dst[:])
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(msg)))
	add16(lenBuf[:])
	sum += ipprotoICMPv6
	add16(msg)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// assertICMP6Checksum checks msg's checksum field against a full recompute
// over src and dst.
func assertICMP6Checksum(t *testing.T, src, dst netip.Addr, msg []byte) {
	t.Helper()
	zeroed := append([]byte{}, msg...)
	zeroed[2], zeroed[3] = 0, 0
	want := icmp6Checksum(src.As16(), dst.As16(), zeroed)
	if got := binary.BigEndian.Uint16(msg[2:4]); got != want {
		t.Errorf("ICMPv6 checksum = %#04x, want %#04x (independent full recompute over %v -> %v)",
			got, want, src, dst)
	}
}

// icmpMessage builds an ICMP message with a zero checksum: the 8-byte header,
// whose second word is an Echo Identifier and Sequence Number or an error's
// type-specific word, followed by body.
func icmpMessage(typ, code uint8, word uint32, body []byte) []byte {
	msg := make([]byte, icmpLen, icmpLen+len(body))
	msg[0] = typ
	msg[1] = code
	binary.BigEndian.PutUint32(msg[4:8], word)
	return append(msg, body...)
}

// echoWord packs an Echo Identifier and Sequence Number 1 into the second word
// of an ICMP header. Every Echo message here is the first of its session.
func echoWord(id uint16) uint32 {
	return uint32(id)<<16 | 1
}

// ip6Packet builds an Ethernet+IPv6 frame around payload, without computing any
// transport checksum.
func ip6Packet(src, dst netip.Addr, nextHeader uint8, payload []byte) []byte {
	pkt := make([]byte, 0, ethLen+ip6Len+len(payload))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x86, 0xDD)
	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(len(payload)))
	pkt = append(pkt, nextHeader, fixtureHopLimit)
	srcBytes := src.As16()
	dstBytes := dst.As16()
	pkt = append(pkt, srcBytes[:]...)
	pkt = append(pkt, dstBytes[:]...)
	return append(pkt, payload...)
}

// buildICMPv6Packet builds an Ethernet+IPv6+ICMPv6 frame with a correct
// checksum.
func buildICMPv6Packet(src, dst netip.Addr, msg []byte) []byte {
	msg = append([]byte{}, msg...)
	binary.BigEndian.PutUint16(msg[2:4], icmp6Checksum(src.As16(), dst.As16(), msg))
	return ip6Packet(src, dst, ipprotoICMPv6, msg)
}

// encapsulate wraps an Ethernet frame's IPv6 packet in the IPv6-in-IPv6 outer
// header a tenant's egress packet arrives at a shard in.
func encapsulate(outerDst, outerSrc netip.Addr, frame []byte) []byte {
	return ip6Packet(outerSrc, outerDst, 41, frame[ethLen:])
}

// nat66Fixture is one NAT66-only shard and one tenant behind it, the setup
// every test in this file shares.
type nat66Fixture struct {
	objs        *NatObjects
	shardSID    netip.Addr
	shardPub    netip.Addr
	backend     netip.Addr
	backendUSID netip.Addr
	peer        netip.Addr
}

func newNAT66Fixture(t *testing.T) nat66Fixture {
	t.Helper()
	requireRoot(t)
	f := nat66Fixture{
		objs:        loadObjects(t),
		shardSID:    netip.MustParseAddr("fc00:1:2::1"),
		shardPub:    netip.MustParseAddr("2001:db8:9999::1"),
		backend:     netip.MustParseAddr("fd20:60::5"),
		backendUSID: netip.MustParseAddr("fc00:3:4::a1b2"),
		peer:        netip.MustParseAddr("2001:db8:9998::1"),
	}
	if err := f.objs.ShardConfigTable.Put(uint32(0), NatShardConfig{
		ShardSid: f.shardSID.As16(), ShardPubAddr6: f.shardPub.As16(), ServesV6: 1,
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}
	return f
}

// run test-runs the dispatcher on pkt.
func (f nat66Fixture) run(t *testing.T, pkt []byte) (uint32, []byte) {
	t.Helper()
	ret, out, err := f.objs.NatIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	return ret, out
}

// ping sends a tenant Echo Request with Identifier fixtureEchoID from usid's
// node through the shard and returns the translated packet as it left, Ethernet
// header included.
func (f nat66Fixture) ping(t *testing.T, usid netip.Addr) []byte {
	t.Helper()
	req := buildICMPv6Packet(f.backend, f.peer, icmpMessage(icmpv6EchoRequest, 0, echoWord(fixtureEchoID), []byte("ping")))
	ret, out := f.run(t, encapsulate(sidWithArgument(f.shardSID, 0x123), usid, req))
	assertLeftFromDatapath(t, ret)
	return out
}

// sendUDP sends a tenant UDP datagram through the shard and returns the
// translated packet as it left.
func (f nat66Fixture) sendUDP(t *testing.T) []byte {
	t.Helper()
	ret, out := f.run(t, buildEncappedUDPPacket(t, sidWithArgument(f.shardSID, 0x123), f.backendUSID,
		f.backend, f.peer, []byte("out")))
	assertLeftFromDatapath(t, ret)
	return out
}

// assertReencapsulated checks that a return-leg packet was re-encapsulated
// toward the tenant's worker node and returns the inner packet, starting at its
// IPv6 header.
//
// The verdict is XDP_DROP against fib_lookup_failed: push_outer_header writes
// the whole packet and then resolves a next hop for a synthetic uSID, which a
// test host cannot. Everything before that step is already in the output.
func (f nat66Fixture) assertReencapsulated(t *testing.T, ret uint32, fibFailedBefore uint64, out []byte) []byte {
	t.Helper()
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d) at the FIB lookup for a synthetic backend uSID", ret, xdpDrop)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibLookupFailed) - fibFailedBefore; got != 1 {
		t.Fatalf("drop_reasons[fib_lookup_failed] rose by %d, want 1 (push_outer_header must have run)", got)
	}
	var outerSrc, outerDst [16]byte
	copy(outerSrc[:], out[ethLen+8:ethLen+24])
	copy(outerDst[:], out[ethLen+24:ethLen+40])
	if outerSrc != f.shardSID.As16() {
		t.Errorf("outer source = %v, want the shard SID %v", netip.AddrFrom16(outerSrc), f.shardSID)
	}
	if outerDst != f.backendUSID.As16() {
		t.Errorf("outer destination = %v, want the tenant's worker uSID %v", netip.AddrFrom16(outerDst), f.backendUSID)
	}
	inner := out[ethLen+ip6Len:]
	if got, want := int(binary.BigEndian.Uint16(out[ethLen+4:ethLen+6])), len(inner); got != want {
		t.Errorf("outer payload length = %d, want %d (the whole inner packet)", got, want)
	}
	return inner
}

func addrAt(b []byte, off int) netip.Addr {
	var a [16]byte
	copy(a[:], b[off:off+16])
	return netip.AddrFrom16(a)
}

// TestNat66ICMPForward_MasqueradesEchoRequest covers nat66_icmp_forward: a
// tenant's ping leaves sourced from the masquerade address, with its Identifier
// replaced by one from the masquerade range and a checksum that verifies, and a
// second ping on the same Identifier keeps the same masquerade Identifier.
func TestNat66ICMPForward_MasqueradesEchoRequest(t *testing.T) {
	f := newNAT66Fixture(t)

	out := f.ping(t, f.backendUSID)

	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
		t.Errorf("EtherType after decap = %#04x, want 0x86DD", got)
	}
	ip6 := out[ethLen:]
	if ip6[6] != ipprotoICMPv6 {
		t.Fatalf("next header = %d, want %d", ip6[6], ipprotoICMPv6)
	}
	if ip6[7] != fixtureHopLimit-1 {
		t.Errorf("hop limit = %d, want %d (decremented once)", ip6[7], fixtureHopLimit-1)
	}
	if got := addrAt(ip6, 8); got != f.shardPub {
		t.Errorf("source = %v, want the masquerade address %v", got, f.shardPub)
	}
	if got := addrAt(ip6, 24); got != f.peer {
		t.Errorf("destination = %v, want %v (untouched)", got, f.peer)
	}

	msg := ip6[ip6Len:]
	if msg[0] != icmpv6EchoRequest {
		t.Errorf("type = %d, want Echo Request", msg[0])
	}
	masqID := binary.BigEndian.Uint16(msg[4:6])
	if masqID < 32768 || masqID >= 32768+28000 {
		t.Errorf("masquerade Identifier %d outside the PAT range", masqID)
	}
	if seq := binary.BigEndian.Uint16(msg[6:8]); seq != 1 {
		t.Errorf("sequence number = %d, want 1 (untouched)", seq)
	}
	assertICMP6Checksum(t, f.shardPub, f.peer, msg)

	again := f.ping(t, f.backendUSID)
	if got := binary.BigEndian.Uint16(again[ethLen+ip6Len+4:]); got != masqID {
		t.Errorf("second ping on the same Identifier masqueraded as %d, want %d (the same session)", got, masqID)
	}
}

// TestNat66ICMPForward_TenantsOnOneIdentifierStayApart covers why the
// Identifier is masqueraded at all: two tenants on different nodes pinging the
// same peer with the same Identifier would otherwise be indistinguishable to
// the peer, and one would receive the other's replies.
func TestNat66ICMPForward_TenantsOnOneIdentifierStayApart(t *testing.T) {
	f := newNAT66Fixture(t)

	first := f.ping(t, f.backendUSID)
	second := f.ping(t, netip.MustParseAddr("fc00:3:5::a1b2"))

	firstID := binary.BigEndian.Uint16(first[ethLen+ip6Len+4:])
	secondID := binary.BigEndian.Uint16(second[ethLen+ip6Len+4:])
	if firstID == secondID {
		t.Errorf("both tenants masqueraded to Identifier %d; replies to one would reach the other", firstID)
	}
}

// TestNat66ICMPForward_NonEchoRequestIsUntranslatable covers the one message a
// tenant can open a flow with. An Echo Reply leaving a tenant answers a request
// this shard never translated, so there is no session to put it in.
func TestNat66ICMPForward_NonEchoRequestIsUntranslatable(t *testing.T) {
	f := newNAT66Fixture(t)

	reply := buildICMPv6Packet(f.backend, f.peer, icmpMessage(icmpv6EchoReply, 0, echoWord(fixtureEchoID), nil))
	ret, _ := f.run(t, encapsulate(sidWithArgument(f.shardSID, 0x123), f.backendUSID, reply))
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatICMPUntranslatable); got != 1 {
		t.Errorf("drop_reasons[icmp_untranslatable] = %d, want 1", got)
	}
}

// TestNat66ICMPReturn_EchoReplyRestoresIdentifier covers the half of a ping
// that is easy to get wrong: restoring the destination address alone is not
// enough, because the tenant's ping matches its reply by Identifier, and it
// would see the masquerade one.
func TestNat66ICMPReturn_EchoReplyRestoresIdentifier(t *testing.T) {
	f := newNAT66Fixture(t)

	out := f.ping(t, f.backendUSID)
	masqID := binary.BigEndian.Uint16(out[ethLen+ip6Len+4:])

	fibFailedBefore := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibLookupFailed)
	reply := buildICMPv6Packet(f.peer, f.shardPub, icmpMessage(icmpv6EchoReply, 0, echoWord(masqID), []byte("ping")))
	ret, out := f.run(t, reply)

	inner := f.assertReencapsulated(t, ret, fibFailedBefore, out)
	if got := addrAt(inner, 8); got != f.peer {
		t.Errorf("inner source = %v, want the peer %v", got, f.peer)
	}
	if got := addrAt(inner, 24); got != f.backend {
		t.Errorf("inner destination = %v, want the tenant %v", got, f.backend)
	}
	msg := inner[ip6Len:]
	if got := binary.BigEndian.Uint16(msg[4:6]); got != fixtureEchoID {
		t.Errorf("Identifier = %#04x, want the tenant's own %#04x", got, fixtureEchoID)
	}
	assertICMP6Checksum(t, f.peer, f.backend, msg)
}

// TestNat66ICMPReturn_TranslatesErrors covers every error type the shard
// translates, each quoting a different packet the shard sent. The tenant must
// receive an error about the packet *it* sent: the quoted source and port or
// Identifier restored, the outer destination its own, the type-specific word
// (a Packet Too Big's MTU) passed through, and one checksum valid over it all.
func TestNat66ICMPReturn_TranslatesErrors(t *testing.T) {
	router := netip.MustParseAddr("2001:db8:7777::1")

	tests := []struct {
		name string
		typ  uint8
		code uint8
		word uint32
		// quote returns the packet the shard sent, starting at its IPv6
		// header, and the tenant-side port or Identifier it masquerades.
		quote func(t *testing.T, f nat66Fixture) ([]byte, uint16)
		// quoteLen truncates the quote, 0 meaning keep all of it.
		quoteLen int
	}{
		{
			name: "packet too big quoting UDP", typ: icmpv6PacketTooBig, word: 1400,
			quote: func(t *testing.T, f nat66Fixture) ([]byte, uint16) {
				return f.sendUDP(t)[ethLen:], encappedSrcPort
			},
		},
		{
			name: "destination unreachable quoting UDP", typ: icmpv6DestUnreach, code: 4,
			quote: func(t *testing.T, f nat66Fixture) ([]byte, uint16) {
				return f.sendUDP(t)[ethLen:], encappedSrcPort
			},
		},
		{
			name: "time exceeded quoting an echo request", typ: icmpv6TimeExceeded,
			quote: func(t *testing.T, f nat66Fixture) ([]byte, uint16) {
				return f.ping(t, f.backendUSID)[ethLen:], fixtureEchoID
			},
		},
		{
			name: "parameter problem quoting UDP", typ: icmpv6ParamProblem, word: 6,
			quote: func(t *testing.T, f nat66Fixture) ([]byte, uint16) {
				return f.sendUDP(t)[ethLen:], encappedSrcPort
			},
		},
		{
			// The minimum any ICMP error is guaranteed to quote: the IP header
			// and the first eight bytes of the transport header.
			name: "packet too big quoting eight bytes of UDP", typ: icmpv6PacketTooBig, word: 1280,
			quoteLen: ip6Len + 8,
			quote: func(t *testing.T, f nat66Fixture) ([]byte, uint16) {
				return f.sendUDP(t)[ethLen:], encappedSrcPort
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newNAT66Fixture(t)
			quoted, tenantPort := tt.quote(t, f)
			if tt.quoteLen != 0 {
				quoted = quoted[:tt.quoteLen]
			}

			fibFailedBefore := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibLookupFailed)
			ret, out := f.run(t, buildICMPv6Packet(router, f.shardPub, icmpMessage(tt.typ, tt.code, tt.word, quoted)))

			inner := f.assertReencapsulated(t, ret, fibFailedBefore, out)
			if got := addrAt(inner, 8); got != router {
				t.Errorf("error source = %v, want the reporting router %v (untouched)", got, router)
			}
			if got := addrAt(inner, 24); got != f.backend {
				t.Errorf("error destination = %v, want the tenant %v", got, f.backend)
			}

			msg := inner[ip6Len:]
			if msg[0] != tt.typ || msg[1] != tt.code {
				t.Errorf("type/code = %d/%d, want %d/%d", msg[0], msg[1], tt.typ, tt.code)
			}
			if got := binary.BigEndian.Uint32(msg[4:8]); got != tt.word {
				t.Errorf("type-specific word = %d, want %d (passed through)", got, tt.word)
			}
			if len(msg) != icmpLen+len(quoted) {
				t.Fatalf("message length = %d, want %d", len(msg), icmpLen+len(quoted))
			}

			gotQuote := msg[icmpLen:]
			if got := addrAt(gotQuote, 8); got != f.backend {
				t.Errorf("quoted source = %v, want the tenant %v", got, f.backend)
			}
			if got := addrAt(gotQuote, 24); got != f.peer {
				t.Errorf("quoted destination = %v, want the peer %v (untouched)", got, f.peer)
			}
			// The port of a quoted UDP header and the Identifier of a quoted
			// Echo Request sit at different offsets.
			portOff := ip6Len
			if gotQuote[6] == ipprotoICMPv6 {
				portOff = ip6Len + 4
			}
			if got := binary.BigEndian.Uint16(gotQuote[portOff:]); got != tenantPort {
				t.Errorf("quoted port or Identifier = %d, want the tenant's own %d", got, tenantPort)
			}
			assertICMP6Checksum(t, router, f.backend, msg)
		})
	}
}

// TestNat66ICMPReturn_Refusals covers every ICMPv6 message addressed to the
// masquerade address that is not translated, and the counter each one lands
// on. A refusal under the wrong reason sends an operator after the wrong
// problem -- malformed is a parse failure, untranslatable a policy outcome.
func TestNat66ICMPReturn_Refusals(t *testing.T) {
	router := netip.MustParseAddr("2001:db8:7777::1")

	tests := []struct {
		name   string
		packet func(t *testing.T, f nat66Fixture) []byte
		reason uint32
	}{
		{
			name: "error quoting a flow with no session",
			packet: func(t *testing.T, f nat66Fixture) []byte {
				quoted := buildUDPPacket(t, f.peer, f.shardPub, 40001, 443, []byte("x"))[ethLen:]
				return buildICMPv6Packet(router, f.shardPub, icmpMessage(icmpv6DestUnreach, 1, 0, quoted))
			},
			reason: DropReasonNat66ICMPNoConn,
		},
		{
			// A real session's tuple, but quoted with a source this shard does
			// not own: the error could not be about a packet it sent.
			name: "error quoting another source",
			packet: func(t *testing.T, f nat66Fixture) []byte {
				quoted := f.sendUDP(t)[ethLen:]
				copy(quoted[8:24], netip.MustParseAddr("2001:db8:1111::1").AsSlice())
				return buildICMPv6Packet(router, f.shardPub, icmpMessage(icmpv6DestUnreach, 1, 0, quoted))
			},
			reason: DropReasonNat66ICMPNoConn,
		},
		{
			name: "echo reply with no session",
			packet: func(t *testing.T, f nat66Fixture) []byte {
				return buildICMPv6Packet(f.peer, f.shardPub, icmpMessage(icmpv6EchoReply, 0, echoWord(40000), nil))
			},
			reason: DropReasonNat66ICMPNoConn,
		},
		{
			name: "error quoting a protocol the shard never sends",
			packet: func(t *testing.T, f nat66Fixture) []byte {
				quoted := ip6Packet(f.shardPub, f.peer, 47, make([]byte, 8))[ethLen:]
				return buildICMPv6Packet(router, f.shardPub, icmpMessage(icmpv6DestUnreach, 1, 0, quoted))
			},
			reason: DropReasonNatICMPUntranslatable,
		},
		{
			name: "error quoting an echo reply",
			packet: func(t *testing.T, f nat66Fixture) []byte {
				quoted := buildICMPv6Packet(f.shardPub, f.peer, icmpMessage(icmpv6EchoReply, 0, echoWord(40000), nil))[ethLen:]
				return buildICMPv6Packet(router, f.shardPub, icmpMessage(icmpv6DestUnreach, 1, 0, quoted))
			},
			reason: DropReasonNatICMPUntranslatable,
		},
		{
			name: "informational type the shard does not handle",
			packet: func(t *testing.T, f nat66Fixture) []byte {
				return buildICMPv6Packet(router, f.shardPub, icmpMessage(130, 0, 0, nil)) // MLD query
			},
			reason: DropReasonNatICMPUntranslatable,
		},
		{
			name: "echo request to the masquerade address",
			packet: func(_ *testing.T, f nat66Fixture) []byte {
				return buildICMPv6Packet(f.peer, f.shardPub, icmpMessage(icmpv6EchoRequest, 0, echoWord(7), nil))
			},
			reason: DropReasonNatICMPUnsolicited,
		},
		{
			name: "truncated ICMPv6 header",
			packet: func(_ *testing.T, f nat66Fixture) []byte {
				return ip6Packet(f.peer, f.shardPub, ipprotoICMPv6, []byte{icmpv6EchoReply, 0, 0, 0})
			},
			reason: DropReasonNat66ICMPMalformed,
		},
		{
			name: "error too short to quote a header",
			packet: func(_ *testing.T, f nat66Fixture) []byte {
				return buildICMPv6Packet(router, f.shardPub, icmpMessage(icmpv6PacketTooBig, 0, 1280, make([]byte, 20)))
			},
			reason: DropReasonNat66ICMPMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newNAT66Fixture(t)
			pkt := tt.packet(t, f)
			ret, _ := f.run(t, pkt)
			if ret != xdpDrop {
				t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
			}
			if got := sumPerCPU(t, f.objs.DropReasons, tt.reason); got != 1 {
				t.Errorf("drop_reasons[%s] = %d, want 1", DropReasonNames[tt.reason], got)
			}
		})
	}
}

// TestNat66ICMPReturn_NeighborDiscoveryPasses covers the one ICMPv6 message a
// masquerade address hands to the kernel. A Neighbor Solicitation for an
// on-link masquerade address that was dropped would make the address
// unreachable.
func TestNat66ICMPReturn_NeighborDiscoveryPasses(t *testing.T) {
	f := newNAT66Fixture(t)

	pkt := buildICMPv6Packet(netip.MustParseAddr("fe80::1"), f.shardPub,
		icmpMessage(icmpv6NeighborSolic, 0, 0, f.shardPub.AsSlice()))
	ret, out := f.run(t, pkt)
	if ret != xdpPass {
		t.Errorf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
	if string(out) != string(pkt) {
		t.Errorf("Neighbor Solicitation modified on its way to the kernel:\n in: % x\nout: % x", pkt, out)
	}
}
