// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// Fixed addresses/ports for the egress (masquerade) tests
// (datum-cloud/enhancements#865), kept distinct from the ingress fixtures
// above so the two test sets never share an address space.
var (
	testEgressBlock  = uint64(0x0123456789ab)
	testEgressNodeID = uint16(0x00cd)

	testTenantArg1 = uint16(0x001)
	testTenantArg2 = uint16(0x002)

	testEgressBackendAddr = "fd00:30:1::5" // a tenant VPC backend Pod's own ULA address
	testEgressDest        = "2600:1f18:1234::50"
	testEgressMasqAddr    = "2001:db8:8::1"
	testWorkerUsid1       = "2001:db8:9::1" // tenant 1's originating worker node
	testWorkerUsid2       = "2001:db8:9::2" // tenant 2's originating worker node
)

const (
	testEgressBackendPort = uint16(54321)
	testEgressDestPort    = uint16(443)
)

// egressSIDAddr builds a uFMT 48+16 address sharing egress_sid's own
// Block+Node-ID (the locator this program's dispatch matches on) with the
// given Argument value as its tenant/VRF identifier (tenant_arg) -- Function
// is fixed at 0 since edge_nat never interprets it (this file's own header
// comment, point 4).
func egressSIDAddr(t *testing.T, arg uint16) netip.Addr {
	t.Helper()
	addr, err := uformat.Encode(uformat.Fields{
		Block: testEgressBlock, NodeID: testEgressNodeID, Function: 0, Argument: arg,
	})
	if err != nil {
		t.Fatalf("uformat.Encode: %v", err)
	}
	return addr
}

// installEgressConfig populates egress_config_table's single entry. The
// stored egress_sid's own Argument bits are irrelevant -- locator_eq only
// ever compares the top 64 bits -- so Argument 0 is used as a placeholder.
func installEgressConfig(t *testing.T, objs *EdgenatObjects) {
	t.Helper()
	cfg := EdgenatEgressConfig{
		EgressSid: egressSIDAddr(t, 0).As16(),
		MasqAddr:  mustAddr(t, testEgressMasqAddr).As16(),
	}
	if err := objs.EgressConfigTable.Put(uint32(0), cfg); err != nil {
		t.Fatalf("populate egress_config_table: %v", err)
	}
}

// ---------------------------------------------------------------------
// SNAT-port probe replica. edgenat.c's handle_egress_forward reuses
// handle_forward's own linear-probe/FNV-1a technique verbatim (design
// plan §2) -- these mirror that computation exactly (including the
// wire-order/htons subtlety documented on this package's own htons
// helper) so tests can force, or assert around, specific masq_port
// outcomes without guessing.
// ---------------------------------------------------------------------

const (
	patProbeLimit        = 8
	patPortBase   uint32 = 32768
	patPortRange  uint32 = 28000
)

// fnv1aFlow replicates edgenat.c's fnv1a_flow bit-for-bit, including __u32
// wraparound (Go's uint32 arithmetic wraps the same way). port must already
// be in the raw wire-order pattern a __be16 field carries (i.e. run through
// htons), matching what the C function actually receives as l4v.sport.
func fnv1aFlow(addr [16]byte, wirePort uint16) uint32 {
	h := uint32(2166136261)
	for i := range 16 {
		h ^= uint32(addr[i])
		h *= 16777619
	}
	h ^= uint32(wirePort & 0xff)
	h *= 16777619
	h ^= uint32(wirePort >> 8)
	h *= 16777619
	return h
}

// predictEgressCandidatePorts replicates handle_egress_forward's SNAT-port
// probe sequence exactly, returning the EDGE_PAT_PROBE_LIMIT host-order
// candidate ports it would try, in probe order, for a given backend/dest
// tuple.
func predictEgressCandidatePorts(backendAddr [16]byte, backendPort, destPort uint16) [patProbeLimit]uint16 {
	base := fnv1aFlow(backendAddr, htons(backendPort)) ^ uint32(htons(destPort))
	var out [patProbeLimit]uint16
	for i := range patProbeLimit {
		out[i] = uint16(patPortBase + (base+uint32(i))%patPortRange)
	}
	return out
}

// TestEdgeNat_EgressForwardSYNAllocatesRewritesAndTransmitsPlain covers the
// full egress forward path end-to-end: a fresh SYN arriving SRv6-
// encapsulated and addressed to egress_sid must be un-wrapped, SNAT'd to
// masq_addr:allocated-port, checksum-fixed, and transmitted as a *plain*
// IPv6 frame (no outer header) -- the one genuinely new tail shape this
// program has (edgenat.c's header comment, point 4).
func TestEdgeNat_EgressForwardSYNAllocatesRewritesAndTransmitsPlain(t *testing.T) {
	backendAddr := mustAddr(t, testEgressBackendAddr)
	destAddr := mustAddr(t, testEgressDest)
	workerUsid := mustAddr(t, testWorkerUsid1)
	masqAddr := mustAddr(t, testEgressMasqAddr)

	env, cleanup := setupTestEnv(t, []netip.Addr{destAddr})
	defer cleanup()

	objs := loadObjects(t)
	installEgressConfig(t, objs)

	pkt := buildEncappedTCPPacket(
		workerUsid, egressSIDAddr(t, testTenantArg1),
		backendAddr, destAddr,
		testEgressBackendPort, testEgressDestPort, true,
	)

	ret, out := runXDP(t, objs.EdgeNat, pkt, env.ifindex)
	if ret != xdpTx {
		t.Fatalf("verdict = %d, want XDP_TX (%d)", ret, xdpTx)
	}

	wantLen := ethHdrLen + ip6HdrLen + tcpHdrLen
	out = out[:wantLen]
	parseEth(t, out)

	ip6 := out[ethHdrLen:]
	if got := netip.AddrFrom16([16]byte(ip6[8:24])); got != masqAddr {
		t.Errorf("saddr (SNAT) = %s, want masq_addr %s", got, masqAddr)
	}
	if got := netip.AddrFrom16([16]byte(ip6[24:40])); got != destAddr {
		t.Errorf("daddr = %s, want unchanged internet destination %s", got, destAddr)
	}

	tcp := ip6[ip6HdrLen:]
	candidates := predictEgressCandidatePorts(backendAddr.As16(), testEgressBackendPort, testEgressDestPort)
	wantSNATPort := candidates[0] // nothing else claimed, so the first probe succeeds
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != wantSNATPort {
		t.Errorf("source port (masq_port) = %d, want %d (first PAT candidate)", got, wantSNATPort)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != testEgressDestPort {
		t.Errorf("dest port = %d, want unchanged %d", got, testEgressDestPort)
	}

	wantCsum := ipv6L4ChecksumZeroed(t, masqAddr, destAddr, tcp)
	if gotCsum := binary.BigEndian.Uint16(tcp[16:18]); gotCsum != wantCsum {
		t.Errorf("TCP checksum = %#04x, want %#04x (independently recomputed)", gotCsum, wantCsum)
	}

	// The forward row must remember the originating worker node's own
	// SRv6 address, captured from the outer header's source before it
	// was stripped (design plan §3.3) -- needed to route the eventual
	// reply back to it.
	fwdKey := EdgenatEgressConnKey{
		Proto:     6,
		Saddr:     backendAddr.As16(),
		Sport:     htons(testEgressBackendPort),
		Daddr:     destAddr.As16(),
		Dport:     htons(testEgressDestPort),
		TenantArg: testTenantArg1,
	}
	var fwd EdgenatEgressConnValue
	if err := objs.EgressConnTable.Lookup(fwdKey, &fwd); err != nil {
		t.Fatalf("read back egress_conn_table forward row: %v", err)
	}
	if got := netip.AddrFrom16(fwd.BackendUsid); got != workerUsid {
		t.Errorf("forward row BackendUsid = %s, want originating worker node %s", got, workerUsid)
	}
	if fwd.MasqPort != htons(wantSNATPort) {
		t.Errorf("forward row MasqPort (wire) = %#04x, want %#04x", fwd.MasqPort, htons(wantSNATPort))
	}

	// A second packet on the same flow (non-SYN) must reuse the existing
	// allocation, not re-probe or drop.
	pkt2 := buildEncappedTCPPacket(
		workerUsid, egressSIDAddr(t, testTenantArg1),
		backendAddr, destAddr,
		testEgressBackendPort, testEgressDestPort, false,
	)
	ret2, out2 := runXDP(t, objs.EdgeNat, pkt2, env.ifindex)
	if ret2 != xdpTx {
		t.Fatalf("second packet verdict = %d, want XDP_TX (%d)", ret2, xdpTx)
	}
	out2 = out2[:wantLen]
	tcp2 := out2[ethHdrLen+ip6HdrLen:]
	if got := binary.BigEndian.Uint16(tcp2[0:2]); got != wantSNATPort {
		t.Errorf("second packet source port = %d, want the same allocated port %d (reused from egress_conn_table)",
			got, wantSNATPort)
	}
}

// TestEdgeNat_EgressReturnDNATsAndEncapsulates covers the egress return
// path: a plain (non-SRv6) reply from an internet peer, addressed to
// masq_addr, must be DNAT'd back to the originating backend Pod,
// checksum-fixed, and re-encapsulated toward that Pod's own worker node --
// the return-trip mirror of the forward test above.
func TestEdgeNat_EgressReturnDNATsAndEncapsulates(t *testing.T) {
	backendAddr := mustAddr(t, testEgressBackendAddr)
	destAddr := mustAddr(t, testEgressDest)
	masqAddr := mustAddr(t, testEgressMasqAddr)
	workerUsid := mustAddr(t, testWorkerUsid1)
	gwAddr := mustAddr(t, testGWAddr)
	const masqPort = uint16(45000)

	env, cleanup := setupTestEnv(t, []netip.Addr{workerUsid})
	defer cleanup()

	objs := loadObjects(t)
	installEgressConfig(t, objs)
	if err := objs.GwConfigTable.Put(uint32(0), EdgenatGwConfig{GwAddr: gwAddr.As16()}); err != nil {
		t.Fatalf("populate gw_config_table: %v", err)
	}

	rev := EdgenatEgressConnKey{
		Proto: 6,
		Saddr: destAddr.As16(),
		Sport: htons(testEgressDestPort),
		Daddr: masqAddr.As16(),
		Dport: htons(masqPort),
	}
	cv := EdgenatEgressConnValue{
		TenantArg:   testTenantArg1,
		BackendAddr: backendAddr.As16(),
		BackendPort: htons(testEgressBackendPort),
		BackendUsid: workerUsid.As16(),
		DestAddr:    destAddr.As16(),
		DestPort:    htons(testEgressDestPort),
		MasqAddr:    masqAddr.As16(),
		MasqPort:    htons(masqPort),
		Proto:       6,
	}
	if err := objs.EgressConnTable.Put(rev, cv); err != nil {
		t.Fatalf("populate egress_conn_table reverse row: %v", err)
	}

	// The reply from the internet peer back to the masquerade address --
	// a plain IPv6 packet, no SRv6 encapsulation, mirroring
	// handle_forward's own "match a plain destination" shape rather than
	// handle_return's "must be SRv6-encapsulated" shape (design plan
	// §3.3).
	pkt := buildTCPPacket(destAddr, masqAddr, testEgressDestPort, masqPort, false)

	ret, out := runXDP(t, objs.EdgeNat, pkt, env.ifindex)
	if ret != xdpTx {
		t.Fatalf("verdict = %d, want XDP_TX (%d)", ret, xdpTx)
	}

	wantLen := ethHdrLen + ip6HdrLen + ip6HdrLen + tcpHdrLen
	out = out[:wantLen]
	parseEth(t, out)

	outer := out[ethHdrLen:]
	if got := outer[6]; got != 41 {
		t.Errorf("outer nexthdr = %d, want 41 (IPv6-in-IPv6)", got)
	}
	if got := netip.AddrFrom16([16]byte(outer[8:24])); got != gwAddr {
		t.Errorf("outer saddr = %s, want this gateway's own address %s", got, gwAddr)
	}
	if got := netip.AddrFrom16([16]byte(outer[24:40])); got != workerUsid {
		t.Errorf("outer daddr = %s, want the originating worker node's uSID %s", got, workerUsid)
	}

	inner := outer[ip6HdrLen:]
	if got := netip.AddrFrom16([16]byte(inner[8:24])); got != destAddr {
		t.Errorf("inner saddr = %s, want unchanged internet peer address %s", got, destAddr)
	}
	if got := netip.AddrFrom16([16]byte(inner[24:40])); got != backendAddr {
		t.Errorf("inner daddr (DNAT) = %s, want backend address %s", got, backendAddr)
	}

	tcp := inner[ip6HdrLen:]
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != testEgressDestPort {
		t.Errorf("source port = %d, want unchanged %d", got, testEgressDestPort)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != testEgressBackendPort {
		t.Errorf("dest port (DNAT) = %d, want backend port %d", got, testEgressBackendPort)
	}

	wantCsum := ipv6L4ChecksumZeroed(t, destAddr, backendAddr, tcp)
	if gotCsum := binary.BigEndian.Uint16(tcp[16:18]); gotCsum != wantCsum {
		t.Errorf("TCP checksum = %#04x, want %#04x (independently recomputed)", gotCsum, wantCsum)
	}
}

// TestEdgeNat_EgressForwardNonSYNWithNoConnDrops covers a non-SYN egress
// packet with no existing egress_conn_table state -- there is no correct
// point to start a new translated flow except a SYN (or, for UDP, any
// first packet), so this must drop, not pass through (egress_sid is
// claimed).
func TestEdgeNat_EgressForwardNonSYNWithNoConnDrops(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	installEgressConfig(t, objs)

	pkt := buildEncappedTCPPacket(
		mustAddr(t, testWorkerUsid1), egressSIDAddr(t, testTenantArg1),
		mustAddr(t, testEgressBackendAddr), mustAddr(t, testEgressDest),
		testEgressBackendPort, testEgressDestPort, false, // ACK, not SYN
	)
	ret, _ := runXDP(t, objs.EdgeNat, pkt, 1)
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}

	got := sumPerCPU(t, objs.DropReasons, DropReasonNoEgressConnNotSyn)
	if got != 1 {
		t.Errorf("drop_reasons[no_egress_conn_not_syn] = %d, want 1", got)
	}
}

// TestEdgeNat_EgressReturnWithNoConnDrops covers a packet addressed to
// masq_addr with no matching egress_conn_table reverse row -- the address
// is claimed, so this must drop, not pass through.
func TestEdgeNat_EgressReturnWithNoConnDrops(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	installEgressConfig(t, objs)

	pkt := buildTCPPacket(mustAddr(t, testEgressDest), mustAddr(t, testEgressMasqAddr), testEgressDestPort, 45000, false)
	ret, _ := runXDP(t, objs.EdgeNat, pkt, 1)
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}

	got := sumPerCPU(t, objs.DropReasons, DropReasonNoEgressReturnConn)
	if got != 1 {
		t.Errorf("drop_reasons[no_egress_return_conn] = %d, want 1", got)
	}
}

// TestEdgeNat_EgressPATExhaustion covers PAT exhaustion on the egress
// forward path: pre-claiming every candidate reverse row a flow's own
// SNAT-port probe would try forces the very first packet on that flow to
// drop with EGRESS_PAT_EXHAUSTED, not silently succeed against some
// other port.
func TestEdgeNat_EgressPATExhaustion(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	installEgressConfig(t, objs)

	backendAddr := mustAddr(t, testEgressBackendAddr)
	destAddr := mustAddr(t, testEgressDest)
	masqAddr := mustAddr(t, testEgressMasqAddr)

	candidates := predictEgressCandidatePorts(backendAddr.As16(), testEgressBackendPort, testEgressDestPort)
	for _, port := range candidates {
		rev := EdgenatEgressConnKey{
			Proto: 6,
			Saddr: destAddr.As16(),
			Sport: htons(testEgressDestPort),
			Daddr: masqAddr.As16(),
			Dport: htons(port),
		}
		if err := objs.EgressConnTable.Put(rev, EdgenatEgressConnValue{}); err != nil {
			t.Fatalf("pre-claim candidate port %d: %v", port, err)
		}
	}

	pkt := buildEncappedTCPPacket(
		mustAddr(t, testWorkerUsid1), egressSIDAddr(t, testTenantArg1),
		backendAddr, destAddr,
		testEgressBackendPort, testEgressDestPort, true,
	)
	ret, _ := runXDP(t, objs.EdgeNat, pkt, 1)
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}

	got := sumPerCPU(t, objs.DropReasons, DropReasonEgressPATExhausted)
	if got != 1 {
		t.Errorf("drop_reasons[egress_pat_exhausted] = %d, want 1", got)
	}
}

// TestEdgeNat_EgressTenantIsolationOnCollidingBackendAddr covers design
// plan §3.1/§3.2's own motivating scenario: two independent tenants happen
// to present the exact same colliding backend_addr:backend_port ->
// dest_addr:dest_port tuple (independent orgs' RFC 4193 self-generated ULA
// prefixes can collide), distinguished only by tenant_arg (carried on each
// packet's own egress_sid destination address). They must resolve to two
// independent egress_conn_table rows and two independent masq_port
// allocations -- neither tenant may observe the other's flow state.
func TestEdgeNat_EgressTenantIsolationOnCollidingBackendAddr(t *testing.T) {
	backendAddr := mustAddr(t, testEgressBackendAddr)
	destAddr := mustAddr(t, testEgressDest)
	worker1 := mustAddr(t, testWorkerUsid1)
	worker2 := mustAddr(t, testWorkerUsid2)

	env, cleanup := setupTestEnv(t, []netip.Addr{destAddr})
	defer cleanup()

	objs := loadObjects(t)
	installEgressConfig(t, objs)

	pkt1 := buildEncappedTCPPacket(
		worker1, egressSIDAddr(t, testTenantArg1),
		backendAddr, destAddr,
		testEgressBackendPort, testEgressDestPort, true,
	)
	ret1, out1 := runXDP(t, objs.EdgeNat, pkt1, env.ifindex)
	if ret1 != xdpTx {
		t.Fatalf("tenant 1 verdict = %d, want XDP_TX (%d)", ret1, xdpTx)
	}

	pkt2 := buildEncappedTCPPacket(
		worker2, egressSIDAddr(t, testTenantArg2),
		backendAddr, destAddr,
		testEgressBackendPort, testEgressDestPort, true,
	)
	ret2, out2 := runXDP(t, objs.EdgeNat, pkt2, env.ifindex)
	if ret2 != xdpTx {
		t.Fatalf("tenant 2 verdict = %d, want XDP_TX (%d)", ret2, xdpTx)
	}

	wantLen := ethHdrLen + ip6HdrLen + tcpHdrLen
	sport1 := binary.BigEndian.Uint16(out1[ethHdrLen+ip6HdrLen : wantLen][0:2])
	sport2 := binary.BigEndian.Uint16(out2[ethHdrLen+ip6HdrLen : wantLen][0:2])
	if sport1 == sport2 {
		t.Errorf("both tenants allocated the same masq_port %d, want two independent allocations", sport1)
	}

	key1 := EdgenatEgressConnKey{
		Proto: 6, Saddr: backendAddr.As16(), Sport: htons(testEgressBackendPort),
		Daddr: destAddr.As16(), Dport: htons(testEgressDestPort), TenantArg: testTenantArg1,
	}
	key2 := key1
	key2.TenantArg = testTenantArg2

	var fwd1, fwd2 EdgenatEgressConnValue
	if err := objs.EgressConnTable.Lookup(key1, &fwd1); err != nil {
		t.Fatalf("read back tenant 1's forward row: %v", err)
	}
	if err := objs.EgressConnTable.Lookup(key2, &fwd2); err != nil {
		t.Fatalf("read back tenant 2's forward row: %v", err)
	}

	if got := netip.AddrFrom16(fwd1.BackendUsid); got != worker1 {
		t.Errorf("tenant 1 forward row BackendUsid = %s, want %s", got, worker1)
	}
	if got := netip.AddrFrom16(fwd2.BackendUsid); got != worker2 {
		t.Errorf("tenant 2 forward row BackendUsid = %s, want %s (must not observe tenant 1's row)", got, worker2)
	}
	if fwd1.MasqPort == fwd2.MasqPort {
		t.Errorf("tenant 1 and tenant 2 forward rows recorded the same MasqPort %#04x, want distinct allocations",
			fwd1.MasqPort)
	}
}
