// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	ipprotoICMP = 1

	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// icmp4Checksum is an independent reference implementation of the ICMPv4
// checksum, which unlike ICMPv6's covers the message alone.
func icmp4Checksum(msg []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(msg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
	}
	if len(msg)%2 == 1 {
		sum += uint32(msg[len(msg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func assertICMP4Checksum(t *testing.T, msg []byte) {
	t.Helper()
	zeroed := append([]byte{}, msg...)
	zeroed[2], zeroed[3] = 0, 0
	if got, want := binary.BigEndian.Uint16(msg[2:4]), icmp4Checksum(zeroed); got != want {
		t.Errorf("ICMPv4 checksum = %#04x, want %#04x (independent full recompute)", got, want)
	}
}

func assertIPv4HeaderChecksum(t *testing.T, ip []byte) {
	t.Helper()
	hdr := append([]byte{}, ip[:ip4Len]...)
	hdr[10], hdr[11] = 0, 0
	if got, want := binary.BigEndian.Uint16(ip[10:12]), ipv4HeaderChecksum(hdr); got != want {
		t.Errorf("IPv4 header checksum = %#04x, want %#04x", got, want)
	}
}

// buildICMPv4Packet builds an Ethernet+IPv4+ICMPv4 frame with correct header
// and ICMP checksums.
func buildICMPv4Packet(src, dst netip.Addr, msg []byte) []byte {
	msg = append([]byte{}, msg...)
	binary.BigEndian.PutUint16(msg[2:4], icmp4Checksum(msg))

	ip := make([]byte, ip4Len)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ip4Len+len(msg)))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = ipprotoICMP
	srcBytes := src.As4()
	dstBytes := dst.As4()
	copy(ip[12:16], srcBytes[:])
	copy(ip[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(ip[10:12], ipv4HeaderChecksum(ip))

	pkt := make([]byte, 0, ethLen+ip4Len+len(msg))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x08, 0x00)
	pkt = append(pkt, ip...)
	return append(pkt, msg...)
}

// nat64Fixture is one dual-family shard and one tenant behind it, pinging an
// IPv4-only peer through its synthesized address.
type nat64Fixture struct {
	nat66Fixture
	shardPub4 netip.Addr
	peer4     netip.Addr
	synth     netip.Addr
}

func newNAT64Fixture(t *testing.T, flags uint8) nat64Fixture {
	t.Helper()
	f := nat64Fixture{
		nat66Fixture: newNAT66Fixture(t),
		shardPub4:    netip.MustParseAddr("192.0.2.10"),
		peer4:        netip.MustParseAddr("198.51.100.7"),
	}
	f.synth = synthesize(nat64Prefix, f.peer4)
	cfg := nat64ShardConfig(f.shardSID, f.shardPub, f.shardPub4)
	cfg.Flags = flags
	if err := f.objs.ShardConfigTable.Put(uint32(0), cfg); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}
	return f
}

// ping64 sends a tenant Echo Request to the synthesized address and returns
// the packet as it left, now IPv4.
func (f nat64Fixture) ping64(t *testing.T) []byte {
	t.Helper()
	msg := icmpMessage(icmpv6EchoRequest, 0, echoWord(fixtureEchoID), []byte("ping"))
	req := buildICMPv6Packet(f.backend, f.synth, msg)
	ret, out := f.run(t, encapsulate(sidWithArgument(f.shardSID, 0x123), f.backendUSID, req))
	assertLeftFromDatapath(t, ret)
	return out
}

// TestNat64ICMPForward_TranslatesEchoRequest covers nat64_icmp_forward: a
// tenant's ICMPv6 Echo Request to a synthesized address leaves as an ICMPv4
// Echo, protocol 1, sourced from the shard's IPv4 address with a masquerade
// Identifier, and both checksums verify. The ICMPv4 checksum is the one with
// teeth: the ICMPv6 pseudo-header it no longer covers has to leave the sum.
func TestNat64ICMPForward_TranslatesEchoRequest(t *testing.T) {
	f := newNAT64Fixture(t, 0)

	out := f.ping64(t)

	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x0800 {
		t.Fatalf("EtherType = %#04x, want 0x0800", got)
	}
	ip := out[ethLen:]
	if ip[9] != ipprotoICMP {
		t.Errorf("protocol = %d, want %d (ICMPv4, not ICMPv6's 58)", ip[9], ipprotoICMP)
	}
	if ip[8] != fixtureHopLimit-1 {
		t.Errorf("TTL = %d, want %d", ip[8], fixtureHopLimit-1)
	}
	if got := netip.AddrFrom4([4]byte(ip[12:16])); got != f.shardPub4 {
		t.Errorf("source = %v, want %v", got, f.shardPub4)
	}
	if got := netip.AddrFrom4([4]byte(ip[16:20])); got != f.peer4 {
		t.Errorf("destination = %v, want %v", got, f.peer4)
	}
	assertIPv4HeaderChecksum(t, ip)

	msg := ip[ip4Len:]
	if msg[0] != icmpEchoRequest || msg[1] != 0 {
		t.Errorf("type/code = %d/%d, want %d/0", msg[0], msg[1], icmpEchoRequest)
	}
	masqID := binary.BigEndian.Uint16(msg[4:6])
	if masqID < 32768 || masqID >= 32768+28000 {
		t.Errorf("masquerade Identifier %d outside the PAT range", masqID)
	}
	if string(msg[icmpLen:]) != "ping" {
		t.Errorf("payload = %q, want %q", msg[icmpLen:], "ping")
	}
	assertICMP4Checksum(t, msg)
}

// TestNat64ICMPReturn_EchoReplyBecomesICMPv6 covers nat64_icmp_return's reply
// path: an ICMPv4 Echo Reply comes back to the tenant as an ICMPv6 one, from
// the synthesized address it pinged, with its own Identifier and a checksum
// that now covers the IPv6 pseudo-header.
func TestNat64ICMPReturn_EchoReplyBecomesICMPv6(t *testing.T) {
	f := newNAT64Fixture(t, 0)

	out := f.ping64(t)
	masqID := binary.BigEndian.Uint16(out[ethLen+ip4Len+4:])

	fibFailedBefore := sumPerCPU(t, f.objs.DropReasons, DropReasonNatFibLookupFailed)
	reply := buildICMPv4Packet(f.peer4, f.shardPub4, icmpMessage(icmpEchoReply, 0, echoWord(masqID), []byte("ping")))
	ret, out := f.run(t, reply)

	inner := f.assertReencapsulated(t, ret, fibFailedBefore, out)
	if inner[6] != ipprotoICMPv6 {
		t.Errorf("next header = %d, want %d", inner[6], ipprotoICMPv6)
	}
	if got := addrAt(inner, 8); got != f.synth {
		t.Errorf("source = %v, want the synthesized address the tenant pinged %v", got, f.synth)
	}
	if got := addrAt(inner, 24); got != f.backend {
		t.Errorf("destination = %v, want the tenant %v", got, f.backend)
	}
	msg := inner[ip6Len:]
	if msg[0] != icmpv6EchoReply {
		t.Errorf("type = %d, want Echo Reply (%d)", msg[0], icmpv6EchoReply)
	}
	if got := binary.BigEndian.Uint16(msg[4:6]); got != fixtureEchoID {
		t.Errorf("Identifier = %#04x, want the tenant's own %#04x", got, fixtureEchoID)
	}
	assertICMP6Checksum(t, f.synth, f.backend, msg)
}

// TestNat64ICMPReturn_EchoReplyWithNoSession covers the counter an unanswered
// ping's stray reply lands on.
func TestNat64ICMPReturn_EchoReplyWithNoSession(t *testing.T) {
	f := newNAT64Fixture(t, 0)

	ret, _ := f.run(t, buildICMPv4Packet(f.peer4, f.shardPub4, icmpMessage(icmpEchoReply, 0, echoWord(40000), nil)))
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNat64ICMPNoConn); got != 1 {
		t.Errorf("drop_reasons[nat64_icmp_no_conn] = %d, want 1", got)
	}
}

// TestEchoResponder covers a ping to the shard's own masquerade address in
// both families: dropped as unsolicited unless the operator turned the
// responder on, and with it on, answered from the address that was pinged with
// a checksum that verifies.
//
// The reply is fully built before its next hop is resolved, which on a test
// host may fail; the bytes are asserted either way.
func TestEchoResponder(t *testing.T) {
	peer4 := netip.MustParseAddr("198.51.100.9")

	t.Run("IPv6 off", func(t *testing.T) {
		f := newNAT64Fixture(t, 0)
		ret, _ := f.run(t, buildICMPv6Packet(f.peer, f.shardPub, icmpMessage(icmpv6EchoRequest, 0, echoWord(7), nil)))
		if ret != xdpDrop {
			t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
		}
		if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatICMPUnsolicited); got != 1 {
			t.Errorf("drop_reasons[icmp_unsolicited] = %d, want 1", got)
		}
	})

	t.Run("IPv6 on", func(t *testing.T) {
		f := newNAT64Fixture(t, ShardFlagEchoResponder)
		req := icmpMessage(icmpv6EchoRequest, 0, echoWord(7), []byte("hello"))
		ret, out := f.run(t, buildICMPv6Packet(f.peer, f.shardPub, req))
		assertLeftFromDatapath(t, ret)
		if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatICMPUnsolicited); got != 0 {
			t.Errorf("drop_reasons[icmp_unsolicited] = %d, want 0 with the responder on", got)
		}

		ip6 := out[ethLen:]
		if got := addrAt(ip6, 8); got != f.shardPub {
			t.Errorf("reply source = %v, want the pinged address %v", got, f.shardPub)
		}
		if got := addrAt(ip6, 24); got != f.peer {
			t.Errorf("reply destination = %v, want the pinger %v", got, f.peer)
		}
		if ip6[7] != 64 {
			t.Errorf("hop limit = %d, want 64", ip6[7])
		}
		msg := ip6[ip6Len:]
		if msg[0] != icmpv6EchoReply {
			t.Errorf("type = %d, want Echo Reply", msg[0])
		}
		if got := binary.BigEndian.Uint16(msg[4:6]); got != 7 {
			t.Errorf("Identifier = %d, want 7 (echoed unchanged)", got)
		}
		if string(msg[icmpLen:]) != "hello" {
			t.Errorf("payload = %q, want %q", msg[icmpLen:], "hello")
		}
		assertICMP6Checksum(t, f.shardPub, f.peer, msg)
	})

	t.Run("IPv4 off", func(t *testing.T) {
		f := newNAT64Fixture(t, 0)
		ret, _ := f.run(t, buildICMPv4Packet(peer4, f.shardPub4, icmpMessage(icmpEchoRequest, 0, echoWord(7), nil)))
		if ret != xdpDrop {
			t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
		}
		if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatICMPUnsolicited); got != 1 {
			t.Errorf("drop_reasons[icmp_unsolicited] = %d, want 1", got)
		}
	})

	t.Run("IPv4 on", func(t *testing.T) {
		f := newNAT64Fixture(t, ShardFlagEchoResponder)
		req := icmpMessage(icmpEchoRequest, 0, echoWord(7), []byte("hello"))
		ret, out := f.run(t, buildICMPv4Packet(peer4, f.shardPub4, req))
		assertLeftFromDatapath(t, ret)

		ip := out[ethLen:]
		if got := netip.AddrFrom4([4]byte(ip[12:16])); got != f.shardPub4 {
			t.Errorf("reply source = %v, want the pinged address %v", got, f.shardPub4)
		}
		if got := netip.AddrFrom4([4]byte(ip[16:20])); got != peer4 {
			t.Errorf("reply destination = %v, want the pinger %v", got, peer4)
		}
		if ip[8] != 64 {
			t.Errorf("TTL = %d, want 64", ip[8])
		}
		assertIPv4HeaderChecksum(t, ip)
		msg := ip[ip4Len:]
		if msg[0] != icmpEchoReply {
			t.Errorf("type = %d, want Echo Reply", msg[0])
		}
		assertICMP4Checksum(t, msg)
	})
}

// icmpBucket mirrors the datapath's struct icmp_bucket.
type icmpBucket struct {
	LastNs   uint64
	CreditNs uint64
}

// TestEchoResponder_RateLimited covers the bucket refusing a reply. Every CPU's
// bucket is emptied and stamped in the future, which the datapath reads as no
// time having passed, so no refill can happen between this write and the test
// run whichever CPU it lands on.
func TestEchoResponder_RateLimited(t *testing.T) {
	f := newNAT64Fixture(t, ShardFlagEchoResponder)

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible CPUs: %v", err)
	}
	empty := make([]icmpBucket, cpus)
	for i := range empty {
		empty[i] = icmpBucket{LastNs: math.MaxUint64}
	}
	if err := f.objs.IcmpRateBucket.Put(uint32(0), empty); err != nil {
		t.Fatalf("empty icmp_rate_bucket: %v", err)
	}

	ret, _ := f.run(t, buildICMPv6Packet(f.peer, f.shardPub, icmpMessage(icmpv6EchoRequest, 0, echoWord(7), nil)))
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, f.objs.DropReasons, DropReasonNatICMPRateLimited); got != 1 {
		t.Errorf("drop_reasons[icmp_rate_limited] = %d, want 1", got)
	}
}
