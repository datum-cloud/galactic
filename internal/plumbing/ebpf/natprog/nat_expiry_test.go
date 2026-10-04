// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// expiryFlow is the NAT66 UDP flow every test in this file drives, against the
// shard every one of them configures.
var (
	expShardSID = netip.MustParseAddr("fc00:1:2::1")
	expShardPub = netip.MustParseAddr("2001:db8:9999::1")
	expBackend  = netip.MustParseAddr("fd20:60::5")
	expUSID     = netip.MustParseAddr("fc00:3:4::a1b2")
	expDest     = netip.MustParseAddr("2001:db8:9998::1")
)

const expTenantArg = 0x123

// monoNow is the datapath's clock, bpf_ktime_get_ns in whole seconds.
func monoNow(t *testing.T) uint32 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("clock_gettime: %v", err)
	}
	return uint32(ts.Sec)
}

// wire16 is a port as the datapath holds it: wire order, read as a host
// integer. These tests run the little-endian object.
func wire16(p uint16) uint16 { return p<<8 | p>>8 }

func setupExpiryShard(t *testing.T) *NatObjects {
	t.Helper()
	requireRoot(t)
	objs := loadObjects(t)
	if err := objs.ShardConfigTable.Put(uint32(0), NatShardConfig{
		ShardSid: expShardSID.As16(), ShardPubAddr6: expShardPub.As16(), ServesV6: 1,
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}
	return objs
}

// sendForward runs one tenant packet of the flow and returns its masquerade
// port, or 0 if the packet was dropped before translation.
func sendForward(t *testing.T, objs *NatObjects) uint16 {
	t.Helper()
	sid := expShardSID.As16()
	sid[8] = (sid[8] & 0xF0) | expTenantArg>>8
	sid[9] = expTenantArg & 0xFF
	pkt := buildEncappedUDPPacket(t, netip.AddrFrom16(sid), expUSID, expBackend, expDest, []byte("out"))
	ret, out, err := objs.NatIngress.Test(pkt)
	if err != nil {
		t.Fatalf("forward test-run: %v", err)
	}
	// A translated packet may still drop at this host's FIB lookup; its
	// rewritten source is what says it was translated.
	const saddrOffset = ethLen + 8
	if ret == xdpPass || len(out) < ethLen+ip6Len+udpLen ||
		netip.AddrFrom16([16]byte(out[saddrOffset:saddrOffset+16])) != expShardPub {
		return 0
	}
	const udpOffset = ethLen + ip6Len
	return binary.BigEndian.Uint16(out[udpOffset : udpOffset+2])
}

func sendReply(t *testing.T, objs *NatObjects, masqPort uint16) {
	t.Helper()
	if _, _, err := objs.NatIngress.Test(buildUDPPacket(t, expShardPub, expDest, encappedDstPort, masqPort,
		[]byte("reply"))); err != nil {
		t.Fatalf("reply test-run: %v", err)
	}
}

func fwdKey() NatConnKey {
	return NatConnKey{
		Family: FamilyIPv6, Proto: ipprotoUDP, TenantArg: expTenantArg,
		Sport: wire16(encappedSrcPort), Dport: wire16(encappedDstPort),
		Saddr: expBackend.As16(), Daddr: expDest.As16(), EncapSrc: expUSID.As16(),
	}
}

func revKey(masqPort uint16) NatConnKey {
	return NatConnKey{
		Family: FamilyIPv6, Proto: ipprotoUDP,
		Sport: wire16(encappedDstPort), Dport: wire16(masqPort),
		Saddr: expDest.As16(), Daddr: expShardPub.As16(),
	}
}

func lookupRow(t *testing.T, objs *NatObjects, key NatConnKey) (NatConnValue, bool) {
	t.Helper()
	var v NatConnValue
	if err := objs.NatConnTable.Lookup(key, &v); err != nil {
		return NatConnValue{}, false
	}
	return v, true
}

func putRow(t *testing.T, objs *NatObjects, key NatConnKey, v NatConnValue) {
	t.Helper()
	if err := objs.NatConnTable.Put(key, v); err != nil {
		t.Fatalf("put nat_conn_table row: %v", err)
	}
}

// ageReverseRow rewrites a reverse row's last_seen to age seconds ago, which
// is how these tests move time: the subtraction wraps the same way the
// datapath's does, so it holds on a host booted more recently than age.
func ageReverseRow(t *testing.T, objs *NatObjects, masqPort uint16, age uint32) NatConnValue {
	t.Helper()
	v, ok := lookupRow(t, objs, revKey(masqPort))
	if !ok {
		t.Fatalf("no reverse row for masquerade port %d", masqPort)
	}
	v.LastSeen = monoNow(t) - age
	putRow(t, objs, revKey(masqPort), v)
	return v
}

func countRows(t *testing.T, objs *NatObjects) int {
	t.Helper()
	var (
		k    NatConnKey
		v    NatConnValue
		rows int
	)
	it := objs.NatConnTable.Iterate()
	for it.Next(&k, &v) {
		rows++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate nat_conn_table: %v", err)
	}
	return rows
}

func assertFresh(t *testing.T, what string, v NatConnValue, now uint32) {
	t.Helper()
	if age := now - v.LastSeen; age > 2 {
		t.Errorf("%s last_seen is %ds old, want refreshed to now", what, age)
	}
}

// candidatePorts is claim_masquerade_port's probe sequence for the test flow.
func candidatePorts() [8]uint16 {
	addr := expBackend.As16()
	h := uint32(2166136261)
	for _, b := range addr {
		h ^= uint32(b)
		h *= 16777619
	}
	sport := wire16(encappedSrcPort)
	h ^= uint32(sport & 0xff)
	h *= 16777619
	h ^= uint32(sport >> 8)
	h *= 16777619
	base := h ^ uint32(wire16(encappedDstPort)) ^ expTenantArg

	var out [8]uint16
	for i := range out {
		out[i] = uint16(32768 + (base+uint32(i))%28000)
	}
	return out
}

// TestSession_RefreshedOnForwardAndReturnHits covers the timestamp both
// directions keep current on the reverse row.
func TestSession_RefreshedOnForwardAndReturnHits(t *testing.T) {
	objs := setupExpiryShard(t)

	port := sendForward(t, objs)
	if port == 0 {
		t.Fatal("first packet was not translated")
	}
	fwd, ok := lookupRow(t, objs, fwdKey())
	if !ok {
		t.Fatal("no forward row after the first packet")
	}
	if fwd.TenantArg != expTenantArg {
		t.Errorf("forward row tenant_arg = %#x, want %#x (a reverse row must name its forward row)",
			fwd.TenantArg, expTenantArg)
	}

	ageReverseRow(t, objs, port, TimeoutUDP-10)
	if got := sendForward(t, objs); got != port {
		t.Fatalf("live session's port changed from %d to %d", port, got)
	}
	rev, _ := lookupRow(t, objs, revKey(port))
	assertFresh(t, "reverse row after a forward hit", rev, monoNow(t))

	ageReverseRow(t, objs, port, TimeoutUDP-10)
	sendReply(t, objs, port)
	rev, _ = lookupRow(t, objs, revKey(port))
	assertFresh(t, "reverse row after a return hit", rev, monoNow(t))
}

// TestSession_ExpiredReverseRowDropsReply covers the return path: once its
// session is idle past the timeout, a reply translates nothing.
func TestSession_ExpiredReverseRowDropsReply(t *testing.T) {
	objs := setupExpiryShard(t)

	port := sendForward(t, objs)
	if port == 0 {
		t.Fatal("first packet was not translated")
	}
	ageReverseRow(t, objs, port, TimeoutUDP+10)

	before := sumPerCPU(t, objs.DropReasons, DropReasonNat66NoReturnConn)
	ret, _, err := objs.NatIngress.Test(buildUDPPacket(t, expShardPub, expDest, encappedDstPort, port,
		[]byte("late")))
	if err != nil {
		t.Fatalf("reply test-run: %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("verdict = %d, want XDP_DROP for a reply to an expired session", ret)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonNat66NoReturnConn) - before; got != 1 {
		t.Errorf("no_return_conn rose by %d, want 1", got)
	}
}

// TestSession_ExpiredForwardRowGetsFreshClaim covers the forward path: an
// expired session is replaced, not resumed, and its old rows are not leaked.
func TestSession_ExpiredForwardRowGetsFreshClaim(t *testing.T) {
	objs := setupExpiryShard(t)

	port := sendForward(t, objs)
	if port == 0 {
		t.Fatal("first packet was not translated")
	}
	old := ageReverseRow(t, objs, port, TimeoutUDP+10)
	// Marks the expired row, so a refresh of it cannot pass for a new one.
	old.Pad = 0xAA
	putRow(t, objs, revKey(port), old)

	got := sendForward(t, objs)
	if got == 0 {
		t.Fatal("packet on an expired session was dropped, want a fresh claim")
	}
	rev, ok := lookupRow(t, objs, revKey(got))
	if !ok {
		t.Fatalf("no reverse row for the fresh claim's port %d", got)
	}
	if rev.Pad == 0xAA {
		t.Error("expired reverse row was resumed, want a fresh session")
	}
	assertFresh(t, "fresh session's reverse row", rev, monoNow(t))
	if n := countRows(t, objs); n != 2 {
		t.Errorf("nat_conn_table rows = %d, want 2 (the expired session released, not leaked)", n)
	}
}

// TestSession_CollisionReclaimsOnlyExpired fills every port the test flow can
// probe with other flows' sessions. While all are live the flow is refused;
// once one expires, that one is released, forward row included, and claimed.
func TestSession_CollisionReclaimsOnlyExpired(t *testing.T) {
	objs := setupExpiryShard(t)
	now := monoNow(t)
	cands := candidatePorts()
	other := netip.MustParseAddr("fd20:60::99")

	victimFwd := func(i int) NatConnKey {
		k := fwdKey()
		k.Saddr = other.As16()
		k.Sport = wire16(uint16(1000 + i))
		return k
	}
	for i, p := range cands {
		v := NatConnValue{
			BackendAddr: other.As16(), BackendPort: wire16(uint16(1000 + i)),
			DestAddr: expDest.As16(), DestPort: wire16(encappedDstPort), ShardPort: wire16(p),
			BackendUsid: expUSID.As16(), Proto: ipprotoUDP, Family: FamilyIPv6,
			TenantArg: expTenantArg, LastSeen: now,
		}
		putRow(t, objs, revKey(p), v)
		putRow(t, objs, victimFwd(i), v)
	}

	before := sumPerCPU(t, objs.DropReasons, DropReasonNat66PatExhausted)
	if got := sendForward(t, objs); got != 0 {
		t.Fatalf("flow claimed port %d with every candidate held by a live session", got)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonNat66PatExhausted) - before; got != 1 {
		t.Errorf("pat_exhausted rose by %d, want 1", got)
	}

	const expired = 3
	ageReverseRow(t, objs, cands[expired], TimeoutUDP+10)

	got := sendForward(t, objs)
	if got != cands[expired] {
		t.Fatalf("claimed port %d, want %d (the one expired candidate)", got, cands[expired])
	}
	rev, _ := lookupRow(t, objs, revKey(got))
	if netip.AddrFrom16(rev.BackendAddr) != expBackend {
		t.Errorf("reclaimed reverse row belongs to %s, want %s", netip.AddrFrom16(rev.BackendAddr), expBackend)
	}
	if _, ok := lookupRow(t, objs, victimFwd(expired)); ok {
		t.Error("expired session's forward row survived its release")
	}
	for i, p := range cands {
		if i == expired {
			continue
		}
		if _, ok := lookupRow(t, objs, victimFwd(i)); !ok {
			t.Errorf("live session on port %d lost its forward row", p)
		}
		if v, _ := lookupRow(t, objs, revKey(p)); netip.AddrFrom16(v.BackendAddr) != other {
			t.Errorf("live session on port %d lost its reverse row", p)
		}
	}
}

// TestSession_OrphanHalvesRepaired covers a session the LRU split. Without its
// forward row, the flow's next packet adopts the live reverse row; without its
// reverse row, the forward row is replaced by a fresh claim.
func TestSession_OrphanHalvesRepaired(t *testing.T) {
	objs := setupExpiryShard(t)

	port := sendForward(t, objs)
	if port == 0 {
		t.Fatal("first packet was not translated")
	}

	if err := objs.NatConnTable.Delete(fwdKey()); err != nil {
		t.Fatalf("delete forward row: %v", err)
	}
	if got := sendForward(t, objs); got != port {
		t.Errorf("flow with an orphan reverse row claimed port %d, want it adopted (%d)", got, port)
	}
	if _, ok := lookupRow(t, objs, fwdKey()); !ok {
		t.Error("forward row not restored for the adopted reverse row")
	}

	if err := objs.NatConnTable.Delete(revKey(port)); err != nil {
		t.Fatalf("delete reverse row: %v", err)
	}
	got := sendForward(t, objs)
	if got == 0 {
		t.Fatal("flow with an orphan forward row was dropped, want a fresh claim")
	}
	if _, ok := lookupRow(t, objs, revKey(got)); !ok {
		t.Errorf("no reverse row behind the forward row's port %d", got)
	}
	if n := countRows(t, objs); n != 2 {
		t.Errorf("nat_conn_table rows = %d, want 2", n)
	}
}
