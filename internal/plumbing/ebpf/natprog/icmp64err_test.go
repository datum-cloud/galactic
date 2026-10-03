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
	icmpDestUnreach   = 3
	icmpTimeExceeded  = 11
	icmpParamProblem  = 12
	icmpSourceQuench  = 4
	icmpRedirect      = 5
	truncatedErrLen   = icmpLen + ip6Len + 8
	quotedTotalLength = 1400
)

// router4 is the IPv4 router every error in this file comes from.
var router4 = netip.MustParseAddr("203.0.113.1")

// sendUDP64 sends a tenant UDP datagram to the synthesized address and returns
// the packet as it left, now IPv4, starting at its IPv4 header.
func (f nat64Fixture) sendUDP64(t *testing.T, payload []byte) []byte {
	t.Helper()
	ret, out := f.run(t, buildEncappedUDPPacket(t, sidWithArgument(f.shardSID, 0x123), f.backendUSID,
		f.backend, f.synth, payload))
	assertLeftFromDatapath(t, ret)
	return out[ethLen:]
}

// translateError sends an ICMPv4 error quoting quoted to the shard and returns
// the translated ICMPv6 packet, starting at its IPv6 header.
func (f nat64Fixture) translateError(t *testing.T, typ, code uint8, word uint32, quoted []byte) []byte {
	t.Helper()
	fibFailedBefore := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibLookupFailed)
	ret, out := f.run(t, buildICMPv4Packet(router4, f.shardPub4, icmpMessage(typ, code, word, quoted)))
	return f.assertReencapsulated(t, ret, fibFailedBefore, out)
}

// TestNat64ICMPError_TranslatesPerRFC7915 covers the type and code mapping of
// RFC 7915 section 4.2 for every ICMPv4 error with an ICMPv6 counterpart, each
// quoting a UDP datagram the shard sent. Every translation is checked whole:
// the outer header from the reporting router's synthesized address, the
// mapped type, code and word, the quoted packet rebuilt as the IPv6 packet the
// tenant sent, and one checksum over all of it.
func TestNat64ICMPError_TranslatesPerRFC7915(t *testing.T) {
	tests := []struct {
		name     string
		typ      uint8
		code     uint8
		word     uint32
		wantType uint8
		wantCode uint8
		wantWord uint32
		// quotedLen, if set, rewrites the quoted packet's Total Length, which
		// a Fragmentation Needed without an MTU is estimated from.
		quotedLen uint16
	}{
		{name: "time exceeded in transit", typ: icmpTimeExceeded, code: 0, wantType: icmpv6TimeExceeded, wantCode: 0},
		{name: "time exceeded reassembly", typ: icmpTimeExceeded, code: 1, wantType: icmpv6TimeExceeded, wantCode: 1},
		{name: "net unreachable", typ: icmpDestUnreach, code: 0, wantType: icmpv6DestUnreach, wantCode: 0},
		{name: "host unreachable", typ: icmpDestUnreach, code: 1, wantType: icmpv6DestUnreach, wantCode: 0},
		{name: "port unreachable", typ: icmpDestUnreach, code: 3, wantType: icmpv6DestUnreach, wantCode: 4},
		{name: "host prohibited", typ: icmpDestUnreach, code: 10, wantType: icmpv6DestUnreach, wantCode: 1},
		{name: "communication prohibited", typ: icmpDestUnreach, code: 13, wantType: icmpv6DestUnreach, wantCode: 1},
		{
			name: "protocol unreachable", typ: icmpDestUnreach, code: 2,
			wantType: icmpv6ParamProblem, wantCode: 1, wantWord: 6,
		},
		{
			name: "fragmentation needed", typ: icmpDestUnreach, code: 4, word: 1300,
			wantType: icmpv6PacketTooBig, wantWord: 1320,
		},
		{
			// RFC 1191's greatest plateau below 1400 is 1006.
			name: "fragmentation needed without an MTU", typ: icmpDestUnreach, code: 4,
			quotedLen: quotedTotalLength, wantType: icmpv6PacketTooBig, wantWord: 1026,
		},
		{
			name: "parameter problem at TTL", typ: icmpParamProblem, code: 0, word: 8 << 24,
			wantType: icmpv6ParamProblem, wantWord: 7,
		},
		{
			name: "parameter problem at destination", typ: icmpParamProblem, code: 0, word: 17 << 24,
			wantType: icmpv6ParamProblem, wantWord: 24,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newNAT64Fixture(t, 0)
			// More than 8 transport bytes, so the truncation is exercised too.
			quoted := f.sendUDP64(t, make([]byte, 200))
			origLen := binary.BigEndian.Uint16(quoted[2:4])
			if tt.quotedLen != 0 {
				binary.BigEndian.PutUint16(quoted[2:4], tt.quotedLen)
				origLen = tt.quotedLen
			}

			ip6 := f.translateError(t, tt.typ, tt.code, tt.word, quoted)

			if got := addrAt(ip6, 8); got != synthesize(nat64Prefix, router4) {
				t.Errorf("source = %v, want the reporting router synthesized, %v", got, synthesize(nat64Prefix, router4))
			}
			if got := addrAt(ip6, 24); got != f.backend {
				t.Errorf("destination = %v, want the tenant %v", got, f.backend)
			}
			if ip6[6] != ipprotoICMPv6 {
				t.Errorf("next header = %d, want %d", ip6[6], ipprotoICMPv6)
			}
			// The whole quote is kept: the message loses the outer IPv4
			// header and its quoted header grows by as much.
			msg := ip6[ip6Len:]
			wantLen := icmpLen + len(quoted) + ip6Len - ip4Len
			if len(msg) != wantLen || int(binary.BigEndian.Uint16(ip6[4:6])) != wantLen {
				t.Fatalf("message length = %d, payload length = %d, want both %d (the whole quote)",
					len(msg), binary.BigEndian.Uint16(ip6[4:6]), wantLen)
			}

			if msg[0] != tt.wantType || msg[1] != tt.wantCode {
				t.Errorf("type/code = %d/%d, want %d/%d", msg[0], msg[1], tt.wantType, tt.wantCode)
			}
			if got := binary.BigEndian.Uint32(msg[4:8]); got != tt.wantWord {
				t.Errorf("type-specific word = %d, want %d", got, tt.wantWord)
			}

			q := msg[icmpLen:]
			if q[0]>>4 != 6 {
				t.Errorf("quoted version = %d, want 6", q[0]>>4)
			}
			if got, want := binary.BigEndian.Uint16(q[4:6]), origLen-ip4Len; got != want {
				t.Errorf("quoted payload length = %d, want %d (the packet as sent, not as quoted)", got, want)
			}
			if q[6] != ipprotoUDP {
				t.Errorf("quoted next header = %d, want %d", q[6], ipprotoUDP)
			}
			if q[7] != fixtureHopLimit-1 {
				t.Errorf("quoted hop limit = %d, want %d (the quoted TTL)", q[7], fixtureHopLimit-1)
			}
			if got := addrAt(q, 8); got != f.backend {
				t.Errorf("quoted source = %v, want the tenant %v", got, f.backend)
			}
			if got := addrAt(q, 24); got != f.synth {
				t.Errorf("quoted destination = %v, want the synthesized address %v", got, f.synth)
			}
			if got := binary.BigEndian.Uint16(q[ip6Len:]); got != encappedSrcPort {
				t.Errorf("quoted source port = %d, want the tenant's own %d", got, encappedSrcPort)
			}
			if got := binary.BigEndian.Uint16(q[ip6Len+2:]); got != encappedDstPort {
				t.Errorf("quoted destination port = %d, want %d (untouched)", got, encappedDstPort)
			}
			if string(q[ip6Len+8:]) != string(quoted[ip4Len+8:]) {
				t.Errorf("quoted bytes past the first 8 transport bytes changed in translation")
			}
			assertICMP6Checksum(t, synthesize(nat64Prefix, router4), f.backend, msg)
		})
	}
}

// TestNat64ICMPError_TruncatesWhenItMust covers the two quotes the shard cuts
// to the rebuilt front instead of carrying whole: one that would make the
// ICMPv6 packet larger than the 1280 bytes RFC 4443 allows, and an RFC 4884
// multi-part message, whose length field the two families keep at different
// offsets. The 8 transport bytes kept still carry the tenant's port, and the
// checksum, computed outright rather than adjusted, still verifies.
func TestNat64ICMPError_TruncatesWhenItMust(t *testing.T) {
	tests := []struct {
		name    string
		payload int
		word    uint32
	}{
		{name: "quote larger than 1280 bytes as ICMPv6", payload: 1300},
		{name: "RFC 4884 length set", payload: 200, word: 32 << 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newNAT64Fixture(t, 0)
			quoted := f.sendUDP64(t, make([]byte, tt.payload))

			ip6 := f.translateError(t, icmpTimeExceeded, 0, tt.word, quoted)

			msg := ip6[ip6Len:]
			if len(msg) != truncatedErrLen || binary.BigEndian.Uint16(ip6[4:6]) != truncatedErrLen {
				t.Fatalf("message length = %d, payload length = %d, want both %d (cut to 8 transport bytes)",
					len(msg), binary.BigEndian.Uint16(ip6[4:6]), truncatedErrLen)
			}
			if got := binary.BigEndian.Uint32(msg[4:8]); got != 0 {
				t.Errorf("type-specific word = %#08x, want 0 (no RFC 4884 length survives the cut)", got)
			}
			if got := binary.BigEndian.Uint16(msg[icmpLen+ip6Len:]); got != encappedSrcPort {
				t.Errorf("quoted source port = %d, want the tenant's own %d", got, encappedSrcPort)
			}
			assertICMP6Checksum(t, synthesize(nat64Prefix, router4), f.backend, msg)
		})
	}
}

// TestNat64ICMPError_QuotingEchoRequest covers an error about a tenant's own
// ping -- what traceroute in ICMP mode reads. The quoted Echo Request goes
// back to ICMPv6, type and Identifier both.
func TestNat64ICMPError_QuotingEchoRequest(t *testing.T) {
	f := newNAT64Fixture(t, 0)

	quoted := f.ping64(t)[ethLen:]
	ip6 := f.translateError(t, icmpTimeExceeded, 0, 0, quoted)

	msg := ip6[ip6Len:]
	if msg[0] != icmpv6TimeExceeded {
		t.Errorf("type = %d, want Time Exceeded", msg[0])
	}
	q := msg[icmpLen:]
	if q[6] != ipprotoICMPv6 {
		t.Errorf("quoted next header = %d, want %d", q[6], ipprotoICMPv6)
	}
	echo := q[ip6Len:]
	if echo[0] != icmpv6EchoRequest {
		t.Errorf("quoted type = %d, want Echo Request (%d)", echo[0], icmpv6EchoRequest)
	}
	if got := binary.BigEndian.Uint16(echo[4:6]); got != fixtureEchoID {
		t.Errorf("quoted Identifier = %#04x, want the tenant's own %#04x", got, fixtureEchoID)
	}
	if got := binary.BigEndian.Uint16(echo[6:8]); got != 1 {
		t.Errorf("quoted Sequence Number = %d, want 1 (untouched)", got)
	}
	assertICMP6Checksum(t, synthesize(nat64Prefix, router4), f.backend, msg)
}

// TestNat64ICMPError_Refusals covers every ICMPv4 error the shard does not
// translate and the counter each lands on.
func TestNat64ICMPError_Refusals(t *testing.T) {
	tests := []struct {
		name   string
		typ    uint8
		code   uint8
		word   uint32
		mangle func(quoted []byte) []byte
		reason uint32
	}{
		// RFC 7915 section 4.2 drops these outright.
		{name: "precedence cutoff in effect", typ: icmpDestUnreach, code: 14,
			reason: DropReasonNatICMPUntranslatable},
		{name: "parameter problem missing option", typ: icmpParamProblem, code: 1,
			reason: DropReasonNatICMPUntranslatable},
		{name: "parameter problem at an untranslatable field", typ: icmpParamProblem, code: 0, word: 4 << 24,
			reason: DropReasonNatICMPUntranslatable},
		{name: "source quench", typ: icmpSourceQuench, reason: DropReasonNatICMPUntranslatable},
		{name: "redirect", typ: icmpRedirect, reason: DropReasonNatICMPUntranslatable},
		{
			name: "quote of another source", typ: icmpDestUnreach, code: 1,
			mangle: func(q []byte) []byte {
				copy(q[12:16], netip.MustParseAddr("192.0.2.99").AsSlice())
				return q
			},
			reason: DropReasonNat64ICMPNoConn,
		},
		{
			name: "quote carrying IPv4 options", typ: icmpDestUnreach, code: 1,
			mangle: func(q []byte) []byte {
				q[0] = 0x46
				return q
			},
			reason: DropReasonNatICMPUntranslatable,
		},
		{
			name: "quote shorter than 8 transport bytes", typ: icmpDestUnreach, code: 1,
			mangle: func(q []byte) []byte { return q[:ip4Len+4] },
			reason: DropReasonNat64ICMPMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newNAT64Fixture(t, 0)
			quoted := f.sendUDP64(t, []byte("out"))
			if tt.mangle != nil {
				quoted = tt.mangle(quoted)
			}
			ret, _ := f.run(t, buildICMPv4Packet(router4, f.shardPub4, icmpMessage(tt.typ, tt.code, tt.word, quoted)))
			if ret != xdpDrop {
				t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
			}
			if got := sumPerCPU(t, f.objs.DropReasons, tt.reason); got != 1 {
				t.Errorf("drop_reasons[%s] = %d, want 1", DropReasonNames[tt.reason], got)
			}
		})
	}
}
