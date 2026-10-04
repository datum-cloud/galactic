// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var wellKnownPrefix = netip.MustParseAddr("64:ff9b::")

// newWKPFixture is newNAT64Fixture with the tenant resolving through a public
// DNS64 resolver: its synthesized address is under the Well-Known Prefix, not
// the shard's NAT64 prefix.
func newWKPFixture(t *testing.T, flags uint8) nat64Fixture {
	t.Helper()
	f := newNAT64Fixture(t, flags)
	f.synth = synthesize(wellKnownPrefix, f.peer4)
	return f
}

// sendUDPTo sends a tenant UDP datagram to dst and returns the verdict and the
// packet as it left.
func (f nat64Fixture) sendUDPTo(t *testing.T, dst netip.Addr) (uint32, []byte) {
	t.Helper()
	return f.run(t, buildEncappedUDPPacket(t, sidWithArgument(f.shardSID, 0x123), f.backendUSID,
		f.backend, dst, []byte("out")))
}

// replyUDP sends the peer's reply to a NAT64 flow that left as out, and returns
// the re-encapsulated inner packet.
func (f nat64Fixture) replyUDP(t *testing.T, out []byte) []byte {
	t.Helper()
	masqPort := binary.BigEndian.Uint16(out[ethLen+ip4Len:])
	fibFailedBefore := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibLookupFailed)
	ret, back := f.run(t, buildIPv4UDPPacket(t, f.shardPub4, f.peer4, encappedDstPort, masqPort, []byte("reply")))
	return f.assertReencapsulated(t, ret, fibFailedBefore, back)
}

func assertNAT64To(t *testing.T, out []byte, src4, dst4 netip.Addr) {
	t.Helper()
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x0800 {
		t.Fatalf("EtherType = %#04x, want 0x0800", got)
	}
	ip := out[ethLen:]
	if got := netip.AddrFrom4([4]byte(ip[12:16])); got != src4 {
		t.Errorf("IPv4 source = %v, want %v", got, src4)
	}
	if got := netip.AddrFrom4([4]byte(ip[16:20])); got != dst4 {
		t.Errorf("IPv4 destination = %v, want %v", got, dst4)
	}
}

// TestNat64WKP_TranslatesAlongsideTheNSP covers a shard with the Well-Known
// Prefix enabled: a flow to either prefix is translated to the same IPv4 peer,
// and each reply comes back from the address that flow's tenant sent to.
func TestNat64WKP_TranslatesAlongsideTheNSP(t *testing.T) {
	f := newWKPFixture(t, ShardFlagWKP)
	nsp := synthesize(nat64Prefix, f.peer4)

	for _, dst := range []netip.Addr{f.synth, nsp} {
		ret, out := f.sendUDPTo(t, dst)
		assertLeftFromDatapath(t, ret)
		assertNAT64To(t, out, f.shardPub4, f.peer4)

		inner := f.replyUDP(t, out)
		if got := addrAt(inner, 8); got != dst {
			t.Errorf("reply source = %v, want the address the tenant sent to %v", got, dst)
		}
		if got := addrAt(inner, 24); got != f.backend {
			t.Errorf("reply destination = %v, want the tenant %v", got, f.backend)
		}
		udp := inner[ip6Len:]
		zeroed := append([]byte{}, udp...)
		zeroed[6], zeroed[7] = 0, 0
		if got, want := binary.BigEndian.Uint16(udp[6:8]), udp6Checksum(dst.As16(), f.backend.As16(), zeroed); got != want {
			t.Errorf("reply UDP checksum = %#04x, want %#04x", got, want)
		}
	}
	if n := countConnRows(t, f.objs); n != 4 {
		t.Errorf("nat_conn_table holds %d rows, want 4 (one flow per prefix, two rows each)", n)
	}
}

// TestNat64WKP_OffIsNAT66 covers a shard without the flag: the Well-Known
// Prefix is an ordinary IPv6 destination, masqueraded as NAT66.
func TestNat64WKP_OffIsNAT66(t *testing.T) {
	f := newWKPFixture(t, 0)

	ret, out := f.sendUDPTo(t, f.synth)
	assertLeftFromDatapath(t, ret)
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
		t.Fatalf("EtherType = %#04x, want 0x86DD (NAT66)", got)
	}
	if got := addrAt(out, ethLen+8); got != f.shardPub {
		t.Errorf("source = %v, want the IPv6 masquerade address %v", got, f.shardPub)
	}
	if got := addrAt(out, ethLen+24); got != f.synth {
		t.Errorf("destination = %v, want %v untouched", got, f.synth)
	}
	for _, reason := range []uint32{DropReasonNat64NonGlobalDest, DropReasonNat64MalformedForward} {
		if got := sumPerCPU(t, f.objs.DropReasons, reason); got != 0 {
			t.Errorf("drop_reasons[%s] = %d, want 0", DropReasonNames[reason], got)
		}
	}
}

// TestNat64WKP_RefusesNonGlobalDestinations covers RFC 6052 section 3.1 under
// the flag rather than under a NAT64 prefix that happens to be 64:ff9b::/96.
func TestNat64WKP_RefusesNonGlobalDestinations(t *testing.T) {
	f := newWKPFixture(t, ShardFlagWKP)

	for i, s := range []string{"10.1.2.3", "192.168.1.1", "100.100.0.1", "203.0.113.1"} {
		ret, _ := f.sendUDPTo(t, synthesize(wellKnownPrefix, netip.MustParseAddr(s)))
		if ret != xdpDrop {
			t.Errorf("%s: verdict = %d, want XDP_DROP (%d)", s, ret, xdpDrop)
		}
		if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNat64NonGlobalDest); got != uint64(i+1) {
			t.Errorf("%s: drop_reasons[nat64_non_global_dest] = %d, want %d", s, got, i+1)
		}
	}
	if n := countConnRows(t, f.objs); n != 0 {
		t.Errorf("nat_conn_table holds %d rows, want 0", n)
	}
}

// TestNat64WKP_Echo covers a tenant ping under the Well-Known Prefix: the
// Echo Request leaves as ICMPv4 and the reply comes back from the address the
// tenant pinged.
func TestNat64WKP_Echo(t *testing.T) {
	f := newWKPFixture(t, ShardFlagWKP)

	out := f.ping64(t)
	assertNAT64To(t, out, f.shardPub4, f.peer4)
	masqID := binary.BigEndian.Uint16(out[ethLen+ip4Len+4:])

	fibFailedBefore := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibLookupFailed)
	ret, back := f.run(t, buildICMPv4Packet(f.peer4, f.shardPub4,
		icmpMessage(icmpEchoReply, 0, echoWord(masqID), []byte("ping"))))
	inner := f.assertReencapsulated(t, ret, fibFailedBefore, back)
	if got := addrAt(inner, 8); got != f.synth {
		t.Errorf("source = %v, want the address the tenant pinged %v", got, f.synth)
	}
	assertICMP6Checksum(t, f.synth, f.backend, inner[ip6Len:])
}

// TestNat64WKP_ICMPError covers an ICMPv4 error about a Well-Known Prefix
// flow: the reporting router is synthesized into the prefix the tenant used,
// and refused when RFC 6052 forbids that prefix from representing it.
func TestNat64WKP_ICMPError(t *testing.T) {
	t.Run("global router", func(t *testing.T) {
		f := newWKPFixture(t, ShardFlagWKP)
		quoted := f.sendUDP64(t, []byte("out"))
		router := netip.MustParseAddr("1.0.0.1")

		fibFailedBefore := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibLookupFailed)
		ret, out := f.run(t, buildICMPv4Packet(router, f.shardPub4, icmpMessage(icmpTimeExceeded, 0, 0, quoted)))
		ip6 := f.assertReencapsulated(t, ret, fibFailedBefore, out)

		want := synthesize(wellKnownPrefix, router)
		if got := addrAt(ip6, 8); got != want {
			t.Errorf("source = %v, want %v", got, want)
		}
		if got := addrAt(ip6[ip6Len+icmpLen:], 24); got != f.synth {
			t.Errorf("quoted destination = %v, want %v", got, f.synth)
		}
		assertICMP6Checksum(t, want, f.backend, ip6[ip6Len:])
	})

	t.Run("non-global router", func(t *testing.T) {
		f := newWKPFixture(t, ShardFlagWKP)
		quoted := f.sendUDP64(t, []byte("out"))

		ret, _ := f.run(t, buildICMPv4Packet(netip.MustParseAddr("10.0.0.1"), f.shardPub4,
			icmpMessage(icmpTimeExceeded, 0, 0, quoted)))
		if ret != xdpDrop {
			t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
		}
		if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatICMPUntranslatable); got != 1 {
			t.Errorf("drop_reasons[icmp_untranslatable] = %d, want 1", got)
		}
	})
}
