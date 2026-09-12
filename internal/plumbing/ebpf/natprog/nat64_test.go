// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

const ip4Len = 20

// nat64Prefix is the /96 every fixture here synthesizes into. Any documented
// NSP would do; what matters is that it is not 64:ff9b::/96, so a test passing
// against a hardcoded well-known prefix would fail.
var nat64Prefix = netip.MustParseAddr("2001:db8:64::")

// v4ToWire converts an IPv4 address to the uint32 shard_config.shard_pub_addr4
// holds. The datapath copies that word onto the wire verbatim, so its native
// byte order has to already be the on-wire byte order -- reading it as
// BigEndian.Uint32 would put the address on the wire backwards on any
// little-endian host.
func v4ToWire(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.NativeEndian.Uint32(a[:])
}

// synthesize builds the IPv6 address DNS64 would hand a tenant for an
// IPv4-only destination: the shared /96 with the IPv4 address in its last four
// bytes (RFC 6052).
func synthesize(prefix, v4 netip.Addr) netip.Addr {
	out := prefix.As16()
	a := v4.As4()
	copy(out[12:], a[:])
	return netip.AddrFrom16(out)
}

// udp4Checksum is an independent reference implementation of the IPv4 UDP
// checksum, used only to build and verify fixtures -- never to exercise
// anything in nat.c. It is deliberately a separate implementation from the
// datapath's incremental diff, which is the whole point: a translation that
// merely agrees with itself proves nothing.
func udp4Checksum(src, dst [4]byte, udpHeaderAndPayload []byte) uint16 {
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
	sum += uint32(ipprotoUDP)
	sum += uint32(len(udpHeaderAndPayload))
	add16(udpHeaderAndPayload)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipv4HeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildIPv4UDPPacket constructs an Ethernet+IPv4+UDP frame with a correct IPv4
// header checksum and a correct UDP checksum -- the shape a reply from the
// IPv4 internet arrives in.
func buildIPv4UDPPacket(t *testing.T, dst, src netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()

	udp := make([]byte, udpLen+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udp4Checksum(src.As4(), dst.As4(), udp))

	ip := make([]byte, ip4Len)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ip4Len+len(udp)))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF
	ip[8] = 64
	ip[9] = ipprotoUDP
	srcBytes := src.As4()
	dstBytes := dst.As4()
	copy(ip[12:16], srcBytes[:])
	copy(ip[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(ip[10:12], ipv4HeaderChecksum(ip))

	pkt := make([]byte, 0, ethLen+ip4Len+len(udp))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x08, 0x00)
	pkt = append(pkt, ip...)
	pkt = append(pkt, udp...)
	return pkt
}

// nat64ShardConfig is the dual-family shard every test in this file runs
// against: it serves NAT66 exactly as before and NAT64 in addition, which is
// the configuration the generalization exists to make possible.
func nat64ShardConfig(shardSID, shardPub netip.Addr, shardPub4 netip.Addr, limit uint32) NatShardConfig {
	return NatShardConfig{
		ShardSid:            shardSID.As16(),
		ShardPubAddr6:       shardPub.As16(),
		Nat64Prefix:         nat64Prefix.As16(),
		ShardPubAddr4:       v4ToWire(shardPub4),
		DefaultSessionLimit: limit,
		ServesV6:            1,
		ServesV4:            1,
	}
}

// sidWithArgument places a tenant's VRFID in the Argument field (bits 69-80) of
// a shard SID, the way a tenant VRF's egress route encapsulates toward it.
func sidWithArgument(shardSID netip.Addr, vrfID uint16) netip.Addr {
	sid := shardSID.As16()
	sid[8] = (sid[8] & 0xF0) | uint8(vrfID>>8&0x0F)
	sid[9] = uint8(vrfID & 0xFF)
	return netip.AddrFrom16(sid)
}

// TestNat64Forward_TranslatesIPv6ToIPv4 covers nat64_forward: a tenant's
// SRv6-encapsulated packet to a synthesized NAT64 address must come out as a
// well-formed IPv4 packet sourced from the shard's own IPv4 address, with both
// checksums verifying against independent full recomputes rather than against
// the datapath's own arithmetic.
func TestNat64Forward_TranslatesIPv6ToIPv4(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	shardPub4 := netip.MustParseAddr("192.0.2.10")
	if err := objs.ShardConfigTable.Put(uint32(0), nat64ShardConfig(shardSID, shardPub, shardPub4, 0)); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	backendAddr := netip.MustParseAddr("fd20:60::5")
	backendUSID := netip.MustParseAddr("fc00:3:4::a1b2")
	peer4 := netip.MustParseAddr("198.51.100.7")
	destAddr := synthesize(nat64Prefix, peer4)

	payload := []byte("nat64 egress payload")
	pkt := buildEncappedUDPPacket(t, sidWithArgument(shardSID, 0x123), backendUSID,
		backendAddr, destAddr, payload)

	ret, out, err := objs.NatIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("verdict = %d, want XDP_PASS (%d) -- a translated packet is handed to the kernel's own "+
			"routing, exactly as the NAT66 forward leg is", ret, xdpPass)
	}

	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x0800 {
		t.Fatalf("ethertype = %#04x, want 0x0800 -- leaving it at IPv6 hands an IPv4 packet to the "+
			"IPv6 receive path", got)
	}
	if len(out) != ethLen+ip4Len+udpLen+len(payload) {
		t.Fatalf("translated length = %d, want %d (IPv6's 40-byte header replaced by IPv4's 20)",
			len(out), ethLen+ip4Len+udpLen+len(payload))
	}

	ip := out[ethLen : ethLen+ip4Len]
	if ip[0] != 0x45 {
		t.Errorf("version/IHL = %#02x, want 0x45", ip[0])
	}
	if got, want := binary.BigEndian.Uint16(ip[2:4]), uint16(ip4Len+udpLen+len(payload)); got != want {
		t.Errorf("tot_len = %d, want %d", got, want)
	}
	if got := binary.BigEndian.Uint16(ip[6:8]); got != 0x4000 {
		t.Errorf("frag_off = %#04x, want 0x4000 (DF set, offset zero)", got)
	}
	if ip[8] != 64 {
		t.Errorf("TTL = %d, want 64 copied from the inner hop limit", ip[8])
	}
	if ip[9] != ipprotoUDP {
		t.Errorf("protocol = %d, want %d", ip[9], ipprotoUDP)
	}
	var gotSrc4, gotDst4 [4]byte
	copy(gotSrc4[:], ip[12:16])
	copy(gotDst4[:], ip[16:20])
	if gotSrc4 != shardPub4.As4() {
		t.Errorf("IPv4 source = %v, want %v (the shard's own masquerade address)",
			netip.AddrFrom4(gotSrc4), shardPub4)
	}
	if gotDst4 != peer4.As4() {
		t.Errorf("IPv4 destination = %v, want %v (the address embedded in the synthesized /96)",
			netip.AddrFrom4(gotDst4), peer4)
	}

	hdrForCsum := append([]byte{}, ip...)
	hdrForCsum[10], hdrForCsum[11] = 0, 0
	if got, want := binary.BigEndian.Uint16(ip[10:12]), ipv4HeaderChecksum(hdrForCsum); got != want {
		t.Errorf("IPv4 header checksum = %#04x, want %#04x (independent full recompute) -- IPv6 carries "+
			"no header checksum, so this one is computed outright rather than adjusted", got, want)
	}

	udpOffset := ethLen + ip4Len
	gotSrcPort := binary.BigEndian.Uint16(out[udpOffset : udpOffset+2])
	gotDstPort := binary.BigEndian.Uint16(out[udpOffset+2 : udpOffset+4])
	if gotDstPort != encappedDstPort {
		t.Errorf("destination port changed unexpectedly: got %d, want %d", gotDstPort, encappedDstPort)
	}
	if gotSrcPort < 32768 || gotSrcPort >= 32768+28000 {
		t.Errorf("allocated masquerade port %d outside the configured PAT range", gotSrcPort)
	}

	gotUDP := out[udpOffset:]
	zeroCsum := append([]byte{}, gotUDP...)
	zeroCsum[6], zeroCsum[7] = 0, 0
	wantCsum := udp4Checksum(shardPub4.As4(), peer4.As4(), zeroCsum)
	if got := binary.BigEndian.Uint16(gotUDP[6:8]); got != wantCsum {
		t.Errorf("UDP checksum after translation = %#04x, want %#04x -- the pseudo-header changed "+
			"address family here, not just address value", got, wantCsum)
	}
}

// TestNat64Return_TranslatesIPv4BackAndReencapsulates covers nat64_return: an
// IPv4 reply must become the IPv6 packet the tenant is expecting -- sourced
// from the synthesized address it originally sent to, not from anything
// IPv4-shaped -- and then be re-encapsulated toward the tenant's worker node.
func TestNat64Return_TranslatesIPv4BackAndReencapsulates(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	shardPub4 := netip.MustParseAddr("192.0.2.10")
	if err := objs.ShardConfigTable.Put(uint32(0), nat64ShardConfig(shardSID, shardPub, shardPub4, 0)); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	backendAddr := netip.MustParseAddr("fd20:60::5")
	backendUSID := netip.MustParseAddr("fc00:3:4::a1b2")
	peer4 := netip.MustParseAddr("198.51.100.7")
	destAddr := synthesize(nat64Prefix, peer4)

	// Forward first, to populate both connection rows and learn the port.
	fwdPkt := buildEncappedUDPPacket(t, sidWithArgument(shardSID, 0x123), backendUSID,
		backendAddr, destAddr, []byte("out"))
	_, fwdOut, err := objs.NatIngress.Test(fwdPkt)
	if err != nil {
		t.Fatalf("forward program test-run: %v", err)
	}
	masqPort := binary.BigEndian.Uint16(fwdOut[ethLen+ip4Len : ethLen+ip4Len+2])

	replyPkt := buildIPv4UDPPacket(t, shardPub4, peer4, encappedDstPort, masqPort, []byte("reply"))

	ret, out, err := objs.NatIngress.Test(replyPkt)
	if err != nil {
		t.Fatalf("return program test-run: %v", err)
	}
	// Same as the NAT66 return leg: push_outer_header's FIB lookup against a
	// synthetic backend uSID cannot resolve on a test host, so the packet is
	// fully translated and then dropped at the last step.
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d) (FIB lookup against a synthetic backend uSID must "+
			"fail on this test host)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonNatFibLookupFailed); got != 1 {
		t.Fatalf("drop_reasons[fib_lookup_failed] = %d, want 1 (push_outer_header must have run)", got)
	}

	// Layout at the drop: eth + outer ip6 + inner ip6 + udp.
	if len(out) != ethLen+ip6Len+ip6Len+udpLen+len("reply") {
		t.Fatalf("length after translate+encap = %d, want %d", len(out),
			ethLen+ip6Len+ip6Len+udpLen+len("reply"))
	}
	// The EtherType is deliberately not asserted here: push_outer_header writes
	// the link header only after its FIB lookup succeeds, and that lookup is the
	// step failing above, so those bytes are still the ones the reply arrived
	// with.
	var gotOuterSrc, gotOuterDst [16]byte
	copy(gotOuterSrc[:], out[ethLen+8:ethLen+24])
	copy(gotOuterDst[:], out[ethLen+24:ethLen+40])
	if gotOuterSrc != shardSID.As16() {
		t.Errorf("outer source = %x, want the shard's own SID %x", gotOuterSrc, shardSID.As16())
	}
	if gotOuterDst != backendUSID.As16() {
		t.Errorf("outer destination = %x, want the tenant's worker uSID %x", gotOuterDst, backendUSID.As16())
	}

	innerOffset := ethLen + ip6Len
	inner := out[innerOffset:]
	if inner[6] != ipprotoUDP {
		t.Errorf("inner next header = %d, want %d", inner[6], ipprotoUDP)
	}
	var gotInnerSrc, gotInnerDst [16]byte
	copy(gotInnerSrc[:], inner[8:24])
	copy(gotInnerDst[:], inner[24:40])
	if gotInnerSrc != destAddr.As16() {
		t.Errorf("inner source = %x, want the synthesized address the tenant sent to %x -- a reply from "+
			"anything else does not match the socket the tenant opened", gotInnerSrc, destAddr.As16())
	}
	if gotInnerDst != backendAddr.As16() {
		t.Errorf("inner destination = %x, want the tenant backend %x", gotInnerDst, backendAddr.As16())
	}

	udpOffset := innerOffset + ip6Len
	if got := binary.BigEndian.Uint16(out[udpOffset+2 : udpOffset+4]); got != encappedSrcPort {
		t.Errorf("restored destination port = %d, want the backend's own port %d", got, encappedSrcPort)
	}

	gotUDP := out[udpOffset:]
	zeroCsum := append([]byte{}, gotUDP...)
	zeroCsum[6], zeroCsum[7] = 0, 0
	wantCsum := udp6Checksum(destAddr.As16(), backendAddr.As16(), zeroCsum)
	if got := binary.BigEndian.Uint16(gotUDP[6:8]); got != wantCsum {
		t.Errorf("UDP checksum after reverse translation = %#04x, want %#04x", got, wantCsum)
	}
}

// TestNat64_TenantIsolationAcrossFamilies proves the conn_key family byte does
// real work: two tenants presenting the identical inner source address, and
// the same tenant's NAT66 and NAT64 flows, must all occupy distinct rows.
func TestNat64_TenantIsolationAcrossFamilies(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	shardPub4 := netip.MustParseAddr("192.0.2.10")
	if err := objs.ShardConfigTable.Put(uint32(0), nat64ShardConfig(shardSID, shardPub, shardPub4, 0)); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	// Deliberately identical on both tenants: the colliding case isolation
	// exists for.
	backendAddr := netip.MustParseAddr("fd20:60::5")
	backendUSID := netip.MustParseAddr("fc00:3:4::a1b2")
	peer4 := netip.MustParseAddr("198.51.100.7")
	nat64Dest := synthesize(nat64Prefix, peer4)
	nat66Dest := netip.MustParseAddr("2001:db8:9998::1")

	run := func(vrfID uint16, dest netip.Addr) {
		pkt := buildEncappedUDPPacket(t, sidWithArgument(shardSID, vrfID), backendUSID,
			backendAddr, dest, []byte("x"))
		if _, _, err := objs.NatIngress.Test(pkt); err != nil {
			t.Fatalf("program test-run (vrf %#x): %v", vrfID, err)
		}
	}

	run(0x123, nat64Dest) // tenant A, NAT64
	run(0x456, nat64Dest) // tenant B, NAT64, identical inner source
	run(0x123, nat66Dest) // tenant A, NAT66, identical inner source

	// Three forward rows and three reverse rows: no pair collapsed into one.
	var (
		key   NatConnKey
		value NatConnValue
		rows  int
	)
	it := objs.NatConnTable.Iterate()
	for it.Next(&key, &value) {
		rows++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate nat_conn_table: %v", err)
	}
	if rows != 6 {
		t.Errorf("nat_conn_table rows = %d, want 6 (three flows, forward and reverse each) -- fewer "+
			"means two tenants' or two families' flows collided in one row", rows)
	}
}

// TestNat64_TenantSessionLimitFailsClosed covers the admission check: a tenant
// at its configured ceiling has the triggering packet dropped, with the cause
// recorded against that tenant rather than only in a shard-wide counter, and
// without disturbing any session it already holds.
func TestNat64_TenantSessionLimitFailsClosed(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	shardPub4 := netip.MustParseAddr("192.0.2.10")
	const limit = 2
	if err := objs.ShardConfigTable.Put(uint32(0),
		nat64ShardConfig(shardSID, shardPub, shardPub4, limit)); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	const vrfID = 0x123
	backendAddr := netip.MustParseAddr("fd20:60::5")
	backendUSID := netip.MustParseAddr("fc00:3:4::a1b2")

	newFlow := func(port uint16) (int, error) {
		dest := synthesize(nat64Prefix, netip.MustParseAddr("198.51.100.7"))
		inner := buildUDPPacket(t, dest, backendAddr, port, encappedDstPort, []byte("x"))[ethLen:]
		pkt := make([]byte, 0, ethLen+ip6Len+len(inner))
		pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
		pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
		pkt = append(pkt, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00)
		pkt = append(pkt, byte(len(inner)>>8), byte(len(inner)), 41, 64)
		srcB := backendUSID.As16()
		dstB := sidWithArgument(shardSID, vrfID).As16()
		pkt = append(pkt, srcB[:]...)
		pkt = append(pkt, dstB[:]...)
		pkt = append(pkt, inner...)
		ret, _, err := objs.NatIngress.Test(pkt)
		return int(ret), err
	}

	for i, port := range []uint16{41000, 41001} {
		ret, err := newFlow(port)
		if err != nil {
			t.Fatalf("flow %d test-run: %v", i, err)
		}
		if ret != xdpPass {
			t.Fatalf("flow %d verdict = %d, want XDP_PASS (%d) -- it is within the limit", i, ret, xdpPass)
		}
	}

	ret, err := newFlow(41002)
	if err != nil {
		t.Fatalf("over-limit flow test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("over-limit verdict = %d, want XDP_DROP (%d) -- a tenant at its ceiling must have the "+
			"triggering packet dropped, never an established session evicted to make room", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonNatTenantLimit); got != 1 {
		t.Errorf("drop_reasons[tenant_session_limit] = %d, want 1", got)
	}

	var ts NatTenantState
	if err := objs.TenantStateTable.Lookup(uint32(vrfID), &ts); err != nil {
		t.Fatalf("lookup tenant_state_table[%#x]: %v", vrfID, err)
	}
	if ts.Sessions != limit {
		t.Errorf("tenant sessions = %d, want %d -- a refused flow must not consume budget", ts.Sessions, limit)
	}
	if ts.AdmitFailLimit != 1 {
		t.Errorf("tenant admit_fail_limit = %d, want 1", ts.AdmitFailLimit)
	}
	if ts.AdmitFailUnavailable != 0 {
		t.Errorf("tenant admit_fail_unavailable = %d, want 0 -- a limit refusal must not be recorded as "+
			"the shard being unable to serve the family", ts.AdmitFailUnavailable)
	}

	// The two admitted flows still translate, proving the ceiling refused only
	// the new one.
	if ret, err := newFlow(41000); err != nil || ret != xdpPass {
		t.Errorf("established flow after the refusal: verdict %d err %v, want XDP_PASS", ret, err)
	}
}

// TestNat64Return_DropsFragmentsAndOptions pins the two shapes this
// implementation deliberately does not handle. Both are counted under their own
// reason rather than passed or lumped together, which is what makes "NAT64
// works except for X" readable off a counter.
func TestNat64Return_DropsFragmentsAndOptions(t *testing.T) {
	requireRoot(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	shardPub4 := netip.MustParseAddr("192.0.2.10")
	peer4 := netip.MustParseAddr("198.51.100.7")

	tests := []struct {
		name    string
		mutate  func(pkt []byte)
		reason  uint32
		reasonN string
	}{
		{
			name: "fragment",
			mutate: func(pkt []byte) {
				// Non-zero fragment offset, MF clear.
				binary.BigEndian.PutUint16(pkt[ethLen+6:ethLen+8], 0x0001)
			},
			reason:  DropReasonNat64V4Fragment,
			reasonN: "nat64_v4_fragment",
		},
		{
			name: "options",
			mutate: func(pkt []byte) {
				pkt[ethLen] = 0x46 // IHL 6: one 4-byte option word
			},
			reason:  DropReasonNat64V4Options,
			reasonN: "nat64_v4_options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := loadObjects(t)
			if err := objs.ShardConfigTable.Put(uint32(0),
				nat64ShardConfig(shardSID, shardPub, shardPub4, 0)); err != nil {
				t.Fatalf("populate shard_config_table: %v", err)
			}

			pkt := buildIPv4UDPPacket(t, shardPub4, peer4, 443, 40000, []byte("x"))
			tt.mutate(pkt)

			ret, _, err := objs.NatIngress.Test(pkt)
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			if ret != xdpDrop {
				t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
			}
			if got := sumPerCPU(t, objs.DropReasons, tt.reason); got != 1 {
				t.Errorf("drop_reasons[%s] = %d, want 1", tt.reasonN, got)
			}
		})
	}
}

// TestNat64Forward_ShardWithoutIPv4AddressIsUnavailable covers the
// half-configured shard: a NAT64 prefix advertised with no public IPv4 address
// to translate into. The refusal is recorded against the tenant under its own
// cause, separable from a limit refusal.
func TestNat64Forward_ShardWithoutIPv4AddressIsUnavailable(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	cfg := nat64ShardConfig(shardSID, netip.MustParseAddr("2001:db8:9999::1"),
		netip.MustParseAddr("192.0.2.10"), 0)
	cfg.ShardPubAddr4 = 0
	if err := objs.ShardConfigTable.Put(uint32(0), cfg); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	const vrfID = 0x123
	dest := synthesize(nat64Prefix, netip.MustParseAddr("198.51.100.7"))
	pkt := buildEncappedUDPPacket(t, sidWithArgument(shardSID, vrfID),
		netip.MustParseAddr("fc00:3:4::a1b2"), netip.MustParseAddr("fd20:60::5"), dest, []byte("x"))

	ret, _, err := objs.NatIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonNat64ShardUnavailable); got != 1 {
		t.Errorf("drop_reasons[nat64_shard_unavailable] = %d, want 1", got)
	}

	var ts NatTenantState
	if err := objs.TenantStateTable.Lookup(uint32(vrfID), &ts); err != nil {
		t.Fatalf("lookup tenant_state_table[%#x]: %v", vrfID, err)
	}
	if ts.AdmitFailUnavailable != 1 {
		t.Errorf("tenant admit_fail_unavailable = %d, want 1", ts.AdmitFailUnavailable)
	}
	if ts.AdmitFailLimit != 0 {
		t.Errorf("tenant admit_fail_limit = %d, want 0 -- an unavailable shard is not a limit refusal, "+
			"and conflating them makes the common failure unanswerable from counters", ts.AdmitFailLimit)
	}
}

// TestNat64_DisabledShardIsUnchanged is the regression guard for the
// generalization's central claim. A shard with no IPv4 fields configured must
// treat a packet destined into the NAT64 prefix exactly as the NAT66-only
// program did: as ordinary NAT66 traffic, translated against the IPv6
// masquerade address, with no NAT64 code path reached at all.
func TestNat64_DisabledShardIsUnchanged(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	shardSID := netip.MustParseAddr("fc00:1:2::1")
	shardPub := netip.MustParseAddr("2001:db8:9999::1")
	if err := objs.ShardConfigTable.Put(uint32(0), NatShardConfig{
		ShardSid: shardSID.As16(), ShardPubAddr6: shardPub.As16(), ServesV6: 1,
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	dest := synthesize(nat64Prefix, netip.MustParseAddr("198.51.100.7"))
	pkt := buildEncappedUDPPacket(t, sidWithArgument(shardSID, 0x123),
		netip.MustParseAddr("fc00:3:4::a1b2"), netip.MustParseAddr("fd20:60::5"), dest, []byte("x"))

	ret, out, err := objs.NatIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x86DD {
		t.Fatalf("ethertype = %#04x, want 0x86DD -- a shard with serves_v4 unset must never translate "+
			"to IPv4, whatever the destination looks like", got)
	}
	var gotSaddr [16]byte
	copy(gotSaddr[:], out[ethLen+8:ethLen+24])
	if gotSaddr != shardPub.As16() {
		t.Errorf("source = %x, want the IPv6 masquerade address %x", gotSaddr, shardPub.As16())
	}
	for _, reason := range []uint32{
		DropReasonNat64ShardUnavailable, DropReasonNat64MalformedForward, DropReasonNat64PatExhausted,
	} {
		if got := sumPerCPU(t, objs.DropReasons, reason); got != 0 {
			t.Errorf("drop_reasons[%s] = %d, want 0 -- no NAT64 path may be reached at all",
				DropReasonNames[reason], got)
		}
	}
}
