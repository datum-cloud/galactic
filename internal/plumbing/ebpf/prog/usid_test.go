// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// Drop reason indices used below are the exported DropReason* constants
// from dropreason.go (this package) -- see that file's doc comment for why
// they're hand-kept in sync with usid.c's `enum drop_reason` rather than
// generated.

const (
	tcActOK       = 0
	tcActShot     = 2
	tcActRedirect = 7

	// tcActUnspec is TC_ACT_UNSPEC (-1 as a C int), which usid.c returns on
	// its fail-open paths (ecv's review of #283: TC_ACT_UNSPEC hands off
	// to the next tc filter on this device, unlike TC_ACT_OK, which ends
	// the chain in direct-action mode). Program.Test reports the verdict
	// as a uint32, i.e. the raw 32 bits of -1's two's-complement
	// representation, not a negative Go int.
	tcActUnspec = uint32(0xFFFFFFFF)
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to load BPF programs and maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// loadObjects loads a fresh copy of the compiled program and its maps into
// the kernel, returning a cleanup-registered *UsidObjects.
func loadObjects(t *testing.T) *UsidObjects {
	t.Helper()

	var objs UsidObjects
	if err := LoadUsidObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load objects: verifier rejected program:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() {
		if err := objs.Close(); err != nil {
			t.Errorf("close objects: %v", err)
		}
	})
	return &objs
}

// testUSID is one synthetic uFMT 48+16 address used across the table
// below. Building it through uformat.Encode (Milestone 2.1) rather than
// hand-packing bytes cross-validates that this program's key-composition
// arithmetic (locator_key/function_key/vrf_key -- see usid.c's map-key
// comment block) agrees with uformat's Go-side field layout.
type testUSID struct {
	block    uint64
	nodeID   uint16
	function uint8
	argument uint16
}

func (u testUSID) addr(t *testing.T) netip.Addr {
	t.Helper()
	addr, err := uformat.Encode(uformat.Fields{
		Block: u.block, NodeID: u.nodeID, Function: u.function, Argument: u.argument,
	})
	if err != nil {
		t.Fatalf("uformat.Encode(%+v): %v", u, err)
	}
	return addr
}

func (u testUSID) locatorKey(t *testing.T) uint64 {
	t.Helper()
	key, err := uformat.LocatorKeyFromAddr(u.addr(t))
	if err != nil {
		t.Fatalf("LocatorKeyFromAddr: %v", err)
	}
	return uint64(key)
}

func (u testUSID) functionKey(t *testing.T) uint64 {
	t.Helper()
	key, err := uformat.NewFunctionKey(u.block, u.function)
	if err != nil {
		t.Fatalf("NewFunctionKey: %v", err)
	}
	return uint64(key)
}

// vrfKey mirrors usid.c's `(block << 12) | argument` composition, via
// uformat.NewVRFKey (Milestone 3.3) -- cross-validating that this
// program's vrf_key arithmetic and uformat's Go-side key composition agree,
// the same way testUSID.addr already does for the address encoding itself.
func (u testUSID) vrfKey() uint64 {
	key, err := uformat.NewVRFKey(u.block, u.argument)
	if err != nil {
		panic(err) // test-table values are always in-range; a panic here means the table itself is broken
	}
	return uint64(key)
}

const ethHeaderLen = 14
const ip6HeaderLen = 40

// innerKind selects what buildPacketWithInner appends after the outer
// IPv6 header, covering every branch of usid.c's step 7 inner-header
// parse (§4.2): a well-formed IPv6 or IPv4 inner packet, an inner header
// whose version nibble matches neither (unknownInnerVersion), one that's
// present but too short to read even its first byte (malformedInner) --
// exercising DROP_REASON_UNKNOWN_INNER_VERSION and
// DROP_REASON_MALFORMED_INNER respectively, alongside the existing
// innerNone/innerV6 coverage -- and innerExtHeaderSRH, which exercises the
// nexthdr gate that now runs before any of those: outer nexthdr names an
// extension header (Routing header/SRH) rather than IPIP/IPv6-in-IPv6, with
// an inner byte that would otherwise misparse as a valid IPv6 version
// nibble if that gate didn't reject the packet first.
type innerKind int

const (
	innerNone innerKind = iota
	innerV6
	innerV4
	innerUnknownVersion
	innerMalformedTruncated
	innerExtHeaderSRH
)

// buildPacket constructs an Ethernet+IPv6 frame whose destination address
// is dst. If withInnerV6 is true, a minimal (header-only, no payload)
// inner IPv6 packet is appended after the outer header, so a program path
// that reaches step 7 (strip) has something well-formed to decapsulate
// into. Thin wrapper over buildPacketWithInner for the two cases every
// existing test needs; new tests exercising the other inner-header
// branches call buildPacketWithInner directly.
func buildPacket(t *testing.T, dst, src netip.Addr, withInnerV6 bool) []byte {
	t.Helper()
	if withInnerV6 {
		return buildPacketWithInner(t, dst, src, innerV6)
	}
	return buildPacketWithInner(t, dst, src, innerNone)
}

// buildPacketWithInner is buildPacket's fuller sibling, selecting the
// inner packet (or lack of one) via kind. See innerKind's doc comment for
// which usid.c branch each value exercises.
func buildPacketWithInner(t *testing.T, dst, src netip.Addr, kind innerKind) []byte {
	t.Helper()

	pkt := make([]byte, 0, ethHeaderLen+ip6HeaderLen+ip6HeaderLen)

	// Ethernet header: arbitrary src/dst MACs, ethertype IPv6.
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA) // h_dest
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB) // h_source
	pkt = append(pkt, 0x86, 0xDD)                         // h_proto = ETH_P_IPV6

	// Outer IPv6 header. nexthdr must now pass usid.c's gate (IPIP=4 or
	// IPv6-in-IPv6=41) for the program to ever peek the inner byte below,
	// so it's set per kind: 4 for the inner-IPv4 case, 43 (Routing
	// header/SRH) for innerExtHeaderSRH specifically to fail that gate,
	// and 41 (the common case) otherwise.
	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00) // version=6, traffic class/flow label = 0
	pkt = append(pkt, 0x00, 0x00)             // payload_len (unchecked by usid_ingress)
	switch kind {
	case innerV4:
		pkt = append(pkt, 4) // nexthdr = IPIP
	case innerExtHeaderSRH:
		pkt = append(pkt, 43) // nexthdr = Routing header (SRH), not a direct inner AF
	default:
		pkt = append(pkt, 41) // nexthdr = IPv6-in-IPv6
	}
	pkt = append(pkt, 64) // hop_limit
	srcBytes := src.As16()
	pkt = append(pkt, srcBytes[:]...)
	dstBytes := dst.As16()
	pkt = append(pkt, dstBytes[:]...)

	switch kind {
	case innerNone:
		// no inner packet at all
	case innerV6:
		pkt = append(pkt, 0x60, 0x00, 0x00, 0x00) // inner version=6
		pkt = append(pkt, 0x00, 0x00)             // payload_len
		pkt = append(pkt, 59)                     // nexthdr = no next header
		pkt = append(pkt, 64)                     // hop_limit
		innerSrc := netip.MustParseAddr("2001:db8::1").As16()
		pkt = append(pkt, innerSrc[:]...)
		innerDst := netip.MustParseAddr("2001:db8::2").As16()
		pkt = append(pkt, innerDst[:]...)
	case innerV4:
		// struct usid_iphdr, 20 bytes packed: ver_ihl, tos, tot_len,
		// id, frag_off, ttl, protocol, check, saddr[4], daddr[4], plus a
		// payload -- bpf_skb_adjust_room (step 7's strip) needs the
		// resulting packet to clear a minimum size the kernel enforces
		// independent of anything usid_ingress itself checks; a
		// header-only inner packet (as innerV6 above effectively is,
		// with no payload) is fine at IPv6's larger 40-byte header size,
		// but a bare 20-byte IPv4 header is not -- confirmed empirically
		// against a real kernel, not a documented constraint. The
		// payload length here is arbitrary, chosen only to clear it with
		// margin; usid_ingress never reads inner payload bytes.
		const innerV4PayloadLen = 60
		pkt = append(pkt, 0x45, 0x00) // version=4, ihl=5; tos=0
		totLen := uint16(20 + innerV4PayloadLen)
		pkt = append(pkt, byte(totLen>>8), byte(totLen)) // tot_len
		pkt = append(pkt, 0x00, 0x00)                    // id
		pkt = append(pkt, 0x00, 0x00)                    // frag_off
		pkt = append(pkt, 64)                            // ttl
		pkt = append(pkt, 59)                            // protocol = no next header
		pkt = append(pkt, 0x00, 0x00)                    // checksum (unchecked by usid_ingress)
		pkt = append(pkt, 198, 51, 100, 1)               // saddr 198.51.100.1
		pkt = append(pkt, 198, 51, 100, 2)               // daddr 198.51.100.2
		pkt = append(pkt, make([]byte, innerV4PayloadLen)...)
	case innerUnknownVersion:
		// A version nibble of 5 matches neither the ==6 nor ==4 branch.
		pkt = append(pkt, 0x50, 0x00, 0x00, 0x00)
		pkt = append(pkt, 0x00, 0x00)
		pkt = append(pkt, 59)
		pkt = append(pkt, 64)
		innerSrc := netip.MustParseAddr("2001:db8::1").As16()
		pkt = append(pkt, innerSrc[:]...)
		innerDst := netip.MustParseAddr("2001:db8::2").As16()
		pkt = append(pkt, innerDst[:]...)
	case innerMalformedTruncated:
		// Present but zero bytes long: usid.c's `(void*)(inner+1) >
		// data_end` bounds check must reject this before even reading
		// the version nibble.
	case innerExtHeaderSRH:
		// A byte that looks exactly like a well-formed IPv6 inner
		// header's version nibble (6) -- proving the program rejects
		// this on outerNextHdr (43, set above) alone, before it ever
		// gets here to read this byte as a version nibble.
		pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
		pkt = append(pkt, 0x00, 0x00)
		pkt = append(pkt, 59)
		pkt = append(pkt, 64)
		innerSrc := netip.MustParseAddr("2001:db8::1").As16()
		pkt = append(pkt, innerSrc[:]...)
		innerDst := netip.MustParseAddr("2001:db8::2").As16()
		pkt = append(pkt, innerDst[:]...)
	}

	return pkt
}

// sumPerCPU reads a per-CPU counter map entry and sums every CPU's slot,
// regardless of which CPU BPF_PROG_TEST_RUN happened to execute on.
func sumPerCPU(t *testing.T, m *ebpf.Map, index uint32) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := m.Lookup(index, &perCPU); err != nil {
		t.Fatalf("lookup drop_reasons[%d]: %v", index, err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// assertOnlyDropReason asserts that exactly one drop_reasons index is
// non-zero (with the expected count), and every other index remains zero
// -- proving the drop was attributed to the right cause and no other path
// was also triggered.
func assertOnlyDropReason(t *testing.T, m *ebpf.Map, want uint32, wantCount uint64) {
	t.Helper()
	for i := range DropReasonCount {
		got := sumPerCPU(t, m, i)
		switch {
		case i == want && got != wantCount:
			t.Errorf("drop_reasons[%d] = %d, want %d", i, got, wantCount)
		case i != want && got != 0:
			t.Errorf("drop_reasons[%d] = %d, want 0 (unexpected drop reason triggered)", i, got)
		}
	}
}

var baseUSID = testUSID{block: 0x0102030405AA, nodeID: 0x0010, function: uformat.FunctionEndDT46, argument: 0x123}

// TestUsidIngress_LocatorMissFailsOpen covers design plan §4.2 step 2 /
// R6: traffic whose destination doesn't match any registered locator_table
// entry (i.e. not one of this node's uSID Blocks) passes through
// completely unmodified -- TC_ACT_OK, no drop counted.
func TestUsidIngress_LocatorMissFailsOpen(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	// Register some other, unrelated /64 -- proves this is a real
	// per-entry miss, not just "the map happens to be empty".
	other := testUSID{block: 0xFFEEDDCCBBAA, nodeID: 0x0002, function: uformat.FunctionEndDT46, argument: 0x001}
	if err := objs.LocatorTable.Put(other.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}

	dst := baseUSID.addr(t)
	src := netip.MustParseAddr("2001:db8:ffff::1")
	pkt := buildPacket(t, dst, src, false)

	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActUnspec {
		t.Errorf("verdict = %d, want TC_ACT_UNSPEC (%d)", ret, tcActUnspec)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet was mutated on a locator_table miss:\n in: % x\nout: % x", pkt, out)
	}
	assertOnlyDropReason(t, objs.DropReasons, 0, 0) // no drop reason should have fired at all
}

// TestUsidIngress_NonIPv6FailsOpen covers R6 for traffic that isn't IPv6
// at all -- verifies step 1's parse gate, not just step 2's lookup.
func TestUsidIngress_NonIPv6FailsOpen(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	if err := objs.LocatorTable.Put(baseUSID.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}

	pkt := buildPacket(t, baseUSID.addr(t), netip.MustParseAddr("2001:db8::1"), false)
	pkt[12], pkt[13] = 0x08, 0x00 // rewrite ethertype to ETH_P_IP

	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActUnspec {
		t.Errorf("verdict = %d, want TC_ACT_UNSPEC (%d)", ret, tcActUnspec)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet was mutated on a non-IPv6 frame:\n in: % x\nout: % x", pkt, out)
	}
}

// TestUsidIngress_UnknownFunctionDropsCounted covers design plan §4.2 step
// 4: a locator_table hit whose Function has no function_table entry is
// dropped, not passed through (the packet was already claimed by the
// locator match), and the drop is attributed to
// DROP_REASON_UNKNOWN_FUNCTION specifically. This also exercises R2/step 3
// indirectly: reaching this drop reason (rather than a locator miss)
// proves Function was correctly read from the unmutated packet.
func TestUsidIngress_UnknownFunctionDropsCounted(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: 0x3, argument: 0x123}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	// Deliberately do not populate function_table for Function 0x3.

	pkt := buildPacket(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), false)

	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet was mutated on a function_table miss:\n in: % x\nout: % x", pkt, out)
	}
	assertOnlyDropReason(t, objs.DropReasons, DropReasonUnknownFunction, 1)
}

// TestUsidIngress_UnsupportedBehaviorDropsCounted covers ecv's review of
// #281: a function_table entry whose behavior isn't BEHAVIOR_END_DT46 (here,
// BEHAVIOR_END_DT2 -- reserved for a future L2 uEnd.DT2 path this program
// doesn't implement) must be dropped and counted as
// DROP_REASON_UNSUPPORTED_BEHAVIOR before step 5/6's Argument/vrf_table
// lookup ever runs, not silently decapsulated as if it were DT46. #740 makes
// Function 0xE and 0xF fully independent service universes (VRF ID + L3
// lookup vs. EVI ID + Bridge Domain MAC lookup); reaching
// DROP_REASON_UNSUPPORTED_BEHAVIOR here, rather than DROP_REASON_UNKNOWN_
// ARGUMENT, proves the behavior gate fired before any vrf_table lookup was
// attempted (vrf_table is deliberately left unpopulated for this Argument).
func TestUsidIngress_UnsupportedBehaviorDropsCounted(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT2, argument: 0x123}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	const behaviorEndDT2 = 2 // usid.c's enum function_behavior; not yet implemented by this program
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: behaviorEndDT2}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	// Deliberately do not populate vrf_table for this Argument.

	pkt := buildPacket(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), false)

	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet was mutated on a behavior-gate drop:\n in: % x\nout: % x", pkt, out)
	}
	assertOnlyDropReason(t, objs.DropReasons, DropReasonUnsupportedBehavior, 1)
}

// TestUsidIngress_UnknownArgumentDropsCounted covers design plan §4.2 step
// 6 and R4: a locator+function match whose Argument has no vrf_table entry
// is dropped and counted as DROP_REASON_UNKNOWN_ARGUMENT. Reaching this
// drop reason (rather than DROP_REASON_UNKNOWN_FUNCTION) proves
// function_table matched and Argument was correctly read at its fixed
// offset with no mutation of the packet -- this is this milestone's "no
// mutation" exit criterion, exercised at the latest point before any
// mutation (bpf_skb_adjust_room) could occur.
func TestUsidIngress_UnknownArgumentDropsCounted(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x123}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	// Deliberately do not populate vrf_table for this Argument.

	pkt := buildPacket(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), false)

	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet mutated on a vrf_table miss (Function/Argument extraction must not mutate, R2):\n in: % x\nout: % x",
			pkt, out)
	}
	assertOnlyDropReason(t, objs.DropReasons, DropReasonUnknownArgument, 1)
}

// TestUsidIngress_ReservedArgumentZeroAlwaysMisses covers design plan R4 /
// §5.1 specifically: Argument 0x000 is reserved and must never be
// registered into vrf_table, so it always misses -- not because of a
// special-cased runtime check, but simply because nothing ever put an
// entry there. This test proves that by registering locator_table and
// function_table (so the packet gets as far as the vrf_table lookup) and
// confirming Argument 0x000 still drops as DROP_REASON_UNKNOWN_ARGUMENT.
func TestUsidIngress_ReservedArgumentZeroAlwaysMisses(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x000}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	// vrf_table intentionally has no entry at all for this Block --
	// not even at key (block<<12 | 0) -- mirroring the real system,
	// where usidmap.Register (design plan §5.1) refuses to ever accept
	// argument==0 in the first place.

	pkt := buildPacket(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), false)

	ret, _, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	assertOnlyDropReason(t, objs.DropReasons, DropReasonUnknownArgument, 1)
}

// TestUsidIngress_VRFTableMatchReachesFIBLookup covers design plan §4.2
// step 6: a full locator+function+vrf_table match. There is no real route
// in the (arbitrary, almost certainly nonexistent) VRF table id used here,
// so bpf_fib_lookup() itself fails -- but reaching DROP_REASON_FIB_LOOKUP_
// FAILED, rather than DROP_REASON_UNKNOWN_ARGUMENT, is only possible if
// vrf_table's entry was found and its vrf_table_id value was read and
// passed into bpf_fib_lookup (step 8), which is exactly what "vrf_table
// match" means. Verifying an actual successful FIB resolution + redirect
// requires a real kernel route/VRF/interface and belongs at the
// integration/e2e layer (design plan §7's testing-strategy table), not
// this BPF_PROG_TEST_RUN-level unit test.
func TestUsidIngress_VRFTableMatchReachesFIBLookup(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x123}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	const bogusVRFTableID = 0x2A2A2A // astronomically unlikely to exist on the test host
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: bogusVRFTableID}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}

	pkt := buildPacket(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), true /* inner IPv6 header present */)

	ret, _, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d) (fib_lookup against a nonexistent VRF table must fail, not succeed)",
			ret, tcActShot)
	}

	got := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed)
	if got != 1 {
		t.Errorf("drop_reasons[fib_lookup_failed] = %d, want 1 (vrf_table entry must have been found and used)", got)
	}
	if unknownArg := sumPerCPU(t, objs.DropReasons, DropReasonUnknownArgument); unknownArg != 0 {
		t.Errorf("drop_reasons[unknown_argument] = %d, want 0 -- vrf_table should have matched, not missed", unknownArg)
	}

	// Confirm the hit counters in vrf_table's own value were updated
	// (design plan R8: per-Argument hit counters back the migration
	// gate's "confirmed zero hits" check).
	var vrfVal UsidVrfValue
	if err := objs.VrfTable.Lookup(usid.vrfKey(), &vrfVal); err != nil {
		t.Fatalf("lookup vrf_table entry: %v", err)
	}
	if vrfVal.Packets != 1 {
		t.Errorf("vrf_table packets = %d, want 1", vrfVal.Packets)
	}
	if vrfVal.Bytes == 0 {
		t.Errorf("vrf_table bytes = 0, want > 0 (skb->len at time of match)")
	}
	if vrfVal.LastSeenNs == 0 {
		t.Errorf("vrf_table last_seen_ns = 0, want a real bpf_ktime_get_ns() reading")
	}
}

// TestUsidIngress_InnerIPv4ReachesFIBLookup covers step 7's inner-IPv4
// branch (usid.c's `inner_version == 4` case), which
// TestUsidIngress_VRFTableMatchReachesFIBLookup above never exercises
// (its packets are always inner-IPv6) -- proving the v4 header actually
// parses (family/addr fields populated, h_proto rewritten) and the
// program reaches the FIB lookup, using the same bogus-VRF-table trick to
// prove that without needing real routing state.
func TestUsidIngress_InnerIPv4ReachesFIBLookup(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x124}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	const bogusVRFTableID = 0x2B2B2B
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: bogusVRFTableID}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}

	pkt := buildPacketWithInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), innerV4)

	ret, _, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d) (fib_lookup against a nonexistent VRF table must fail, not succeed)",
			ret, tcActShot)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed); got != 1 {
		t.Errorf("drop_reasons[fib_lookup_failed] = %d, want 1 (inner-IPv4 must parse and reach FIB lookup)", got)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonUnknownInnerVer); got != 0 {
		t.Errorf("drop_reasons[unknown_inner_version] = %d, want 0 -- a v4 header must not be misclassified", got)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonMalformedInner); got != 0 {
		t.Errorf("drop_reasons[malformed_inner] = %d, want 0 -- a well-formed v4 header must parse cleanly", got)
	}
}

// TestUsidIngress_UnknownInnerVersionDropped covers the inner-header
// version nibble matching neither 6 nor 4 (usid.c's final `else` branch
// of step 7's parse) -- a case no other test exercises.
func TestUsidIngress_UnknownInnerVersionDropped(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x125}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: 0x2C2C2C}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}

	pkt := buildPacketWithInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), innerUnknownVersion)

	ret, _, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	assertOnlyDropReason(t, objs.DropReasons, DropReasonUnknownInnerVer, 1)
}

// TestUsidIngress_UnexpectedNextHdrDropped covers the nexthdr gate ahead of
// step 7's inner-header parse: outer ip6->nexthdr naming an extension
// header (here, a Routing header/SRH -- the shape a peer still on full
// encap, rather than uSID reduced encap, would send) must be dropped and
// counted as DROP_REASON_UNEXPECTED_NEXTHDR, distinctly from
// DROP_REASON_UNKNOWN_INNER_VERSION -- even though the byte sitting at the
// inner-header offset is a well-formed IPv6 version nibble that would
// otherwise pass the version check. Before this gate existed, this exact
// packet shape was misread as the inner packet itself and produced no
// distinguishable signal from a genuinely malformed/garbled inner header.
func TestUsidIngress_UnexpectedNextHdrDropped(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x127}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: 0x2E2E2E}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}

	pkt := buildPacketWithInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), innerExtHeaderSRH)

	ret, _, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	assertOnlyDropReason(t, objs.DropReasons, DropReasonUnexpectedNextHdr, 1)
}

// TestUsidIngress_MalformedInnerDropped covers an inner packet present in
// name only (zero bytes after the stripped outer header) -- usid.c's
// bounds check on `inner+1 > data_end` must reject this before even
// reading the version nibble, rather than reading past the packet.
func TestUsidIngress_MalformedInnerDropped(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x126}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: 0x2D2D2D}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}

	pkt := buildPacketWithInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), innerMalformedTruncated)

	ret, _, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	assertOnlyDropReason(t, objs.DropReasons, DropReasonMalformedInner, 1)
}

// TestUsidIngress_VRFTableKeyIncludesBlock covers design plan R8/§4.4's
// requirement that vrf_table's key is (Block, Argument), not Argument
// alone: two uSID Blocks sharing the same Argument value (as R8's
// make-before-break migration deliberately produces -- one live entry
// under an old Block, one under a new one) must be counted and matched
// independently. Registering vrf_table only under Block A and sending a
// packet for the *same* Argument under Block B must still miss, proving
// the program's vrf_key composition genuinely folds in the matched Block
// rather than only the Argument bits.
func TestUsidIngress_VRFTableKeyIncludesBlock(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	const sharedArgument = 0x123
	blockA := testUSID{block: 0x0102030405AA, nodeID: 0x0010, function: uformat.FunctionEndDT46, argument: sharedArgument}
	blockB := testUSID{block: 0x0A0B0C0D0E0F, nodeID: 0x0011, function: uformat.FunctionEndDT46, argument: sharedArgument}

	for _, u := range []testUSID{blockA, blockB} {
		if err := objs.LocatorTable.Put(u.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
			t.Fatalf("populate locator_table for block %#x: %v", u.block, err)
		}
		if err := objs.FunctionTable.Put(u.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
			t.Fatalf("populate function_table for block %#x: %v", u.block, err)
		}
	}
	// Only Block A gets a vrf_table entry for the shared Argument.
	if err := objs.VrfTable.Put(blockA.vrfKey(), UsidVrfValue{VrfTableId: 0x2A2A2A}); err != nil {
		t.Fatalf("populate vrf_table for block A: %v", err)
	}

	pkt := buildPacket(t, blockB.addr(t), netip.MustParseAddr("2001:db8::1"), false)

	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d) -- Block B has no vrf_table entry for this Argument", ret, tcActShot)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet mutated on a vrf_table miss:\n in: % x\nout: % x", pkt, out)
	}
	assertOnlyDropReason(t, objs.DropReasons, DropReasonUnknownArgument, 1)

	// Block A's entry must be completely untouched by Block B's packet.
	var vrfVal UsidVrfValue
	if err := objs.VrfTable.Lookup(blockA.vrfKey(), &vrfVal); err != nil {
		t.Fatalf("lookup vrf_table entry for block A: %v", err)
	}
	if vrfVal.Packets != 0 {
		t.Errorf("block A's vrf_table packets = %d, want 0 -- Block B's packet must not match Block A's entry",
			vrfVal.Packets)
	}
}

// buildPacketWithV6Addrs is buildPacketWithInner's sibling for tests that
// need to control the *inner* packet's own source/destination (the DSR
// redesign's NPTv6/vip_xlat tests below) -- innerV6's own hardcoded
// addresses aren't enough there.
func buildPacketWithV6Addrs(t *testing.T, outerDst, outerSrc, innerSrc, innerDst netip.Addr) []byte {
	t.Helper()

	pkt := make([]byte, 0, ethHeaderLen+ip6HeaderLen+ip6HeaderLen+4)
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x86, 0xDD)

	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	pkt = append(pkt, 0x00, 0x00)
	pkt = append(pkt, 41) // nexthdr = IPv6-in-IPv6
	pkt = append(pkt, 64)
	srcBytes := outerSrc.As16()
	pkt = append(pkt, srcBytes[:]...)
	dstBytes := outerDst.As16()
	pkt = append(pkt, dstBytes[:]...)

	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	pkt = append(pkt, 0x00, 0x00)
	pkt = append(pkt, 59) // nexthdr = no next header (plain address test, no L4)
	pkt = append(pkt, 64)
	innerSrcBytes := innerSrc.As16()
	pkt = append(pkt, innerSrcBytes[:]...)
	innerDstBytes := innerDst.As16()
	pkt = append(pkt, innerDstBytes[:]...)

	return pkt
}

// nptv6Prefix48 packs prefix's first 48 bits into a 16-byte, zero-padded
// array -- the wire layout UsidNptv6Value.UlaPrefix/PublicPrefix expect,
// matching internal/plumbing/nptv6.prefixChecksum's identical assumption.
func nptv6Prefix48(t *testing.T, prefix string) [16]byte {
	t.Helper()
	addr, err := netip.ParseAddr(prefix)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", prefix, err)
	}
	return addr.As16()
}

// TestUsidIngress_NPTv6TranslatesDestinationBeforeFIBLookup covers the DSR
// redesign's component 2 (design plan §2): an inner packet's destination
// must be translated from the tenant's PublicPrefix back to its own
// ULAPrefix *before* the FIB lookup (step 8), using the same RFC 6296 §3.6
// worked example internal/plumbing/nptv6's own test vector pins
// (FD01:0203:0405::/48 <-> 2001:0DB8:0001::/48, adjustment 0xD54F) --
// cross-validating the C and Go implementations of the identical algorithm
// against the identical published numbers. As in
// TestUsidIngress_VRFTableMatchReachesFIBLookup, the FIB lookup itself
// still fails (no real route for the bogus VRF table id), but reaching
// DROP_REASON_FIB_LOOKUP_FAILED -- and, more directly, the translated
// destination bytes actually present in the returned packet -- can only
// happen if the translation ran first.
func TestUsidIngress_NPTv6TranslatesDestinationBeforeFIBLookup(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x321}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	const bogusVRFTableID = 0x2B2B2B
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: bogusVRFTableID}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
	if err := objs.Nptv6Table.Put(usid.vrfKey(), UsidNptv6Value{
		UlaPrefix:    nptv6Prefix48(t, "fd01:203:405::"),
		PublicPrefix: nptv6Prefix48(t, "2001:db8:1::"),
		PrefixLen:    48,
		Adjustment:   0xD54F,
	}); err != nil {
		t.Fatalf("populate nptv6_table: %v", err)
	}

	// Inner destination is the tenant's PUBLIC address -- specifically the
	// RFC 6296 §3.6 worked example's own *forward*-translated address
	// (2001:0DB8:0001:D550::1234, itself FD01:0203:0405:0001::1234's
	// public form), so this test's expected reverse-translated ULA result
	// is the RFC's own published number, not an arbitrarily chosen public
	// address whose "expected" ULA would have to be independently derived
	// (subnet words aren't equal across the translation, only offset by
	// the adjustment -- picking a public subnet word with no known-correct
	// ULA counterpart would make this test's own expectation the thing
	// that needs proving).
	innerDst := netip.MustParseAddr("2001:db8:1:d550::1234")
	innerSrc := netip.MustParseAddr("2001:db8:ffff::1")
	pkt := buildPacketWithV6Addrs(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), innerSrc, innerDst)

	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed); got != 1 {
		t.Errorf("drop_reasons[fib_lookup_failed] = %d, want 1 (nptv6 lookup must not have short-circuited processing)", got)
	}

	// Post-strip layout: eth(14) + inner ip6 header, daddr at bytes
	// 14+24..14+40 (vtc_flow(4)+payload_len(2)+nexthdr(1)+hop_limit(1)+
	// saddr(16) = 24 bytes precede daddr).
	const daddrOffset = ethHeaderLen + 24
	if len(out) < daddrOffset+16 {
		t.Fatalf("output packet too short (%d bytes) to contain a translated daddr", len(out))
	}
	wantDaddr := netip.MustParseAddr("fd01:203:405:1::1234").As16() // == FD01:0203:0405:0001::1234
	var gotDaddr [16]byte
	copy(gotDaddr[:], out[daddrOffset:daddrOffset+16])
	if gotDaddr != wantDaddr {
		t.Errorf("inner daddr after NPTv6 translation = %x, want %x (RFC 6296 §3.6 worked example)",
			gotDaddr, wantDaddr)
	}

	// The inner source (not covered by this VRF's translation direction)
	// must be left completely unmodified.
	const saddrOffset = ethHeaderLen + 8
	wantSaddr := innerSrc.As16()
	var gotSaddr [16]byte
	copy(gotSaddr[:], out[saddrOffset:saddrOffset+16])
	if gotSaddr != wantSaddr {
		t.Errorf("inner saddr changed unexpectedly: got %x, want %x", gotSaddr, wantSaddr)
	}
}

// udp6Checksum computes RFC 2460 §8.1's IPv6 UDP checksum from scratch
// (1's-complement sum of the pseudo-header + UDP header + payload, then
// complemented) -- an independent reference implementation used only to
// verify apply_vip_xlat's *incremental* bpf_l4_csum_replace update landed
// on the identical final value a full recompute would, not to exercise
// anything in usid.c itself.
func udp6Checksum(src, dst [16]byte, udpHeaderAndPayload []byte) uint16 {
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
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(udpHeaderAndPayload)))
	add16(lenBuf[:])
	sum += uint32(17) // next header = UDP, the other 3 pseudo-header bytes are zero
	add16(udpHeaderAndPayload)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// TestUsidIngress_VIPXlatRewritesAddrPortAndChecksum covers the DSR
// redesign's component 0.1 tap-VIP substitution (design plan §0.1): an
// inner UDP packet destined to VIPAddress:VIPPort must be rewritten to
// BackendAddress:BackendPort *and* have a checksum that verifies against
// an independent full recompute -- proving apply_vip_xlat's incremental
// bpf_l4_csum_replace calls, not just the address/port bytes themselves,
// are correct. This is the one rewrite in usid.c with no other test
// coverage anywhere in this repo (no tap/VM containerlab fixture exists
// yet -- design plan §8) and the residual-risk note in apply_vip_xlat's
// own doc comment refers to; this test is the first real evidence for it.
func TestUsidIngress_VIPXlatRewritesAddrPortAndChecksum(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	usid := testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x654}
	if err := objs.LocatorTable.Put(usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := objs.FunctionTable.Put(usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	const bogusVRFTableID = 0x2C2C2C
	if err := objs.VrfTable.Put(usid.vrfKey(), UsidVrfValue{VrfTableId: bogusVRFTableID}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}

	vip := netip.MustParseAddr("2001:db8:5:5::100")
	backend := netip.MustParseAddr("fd20:60::5:5")
	const vipPort, backendPort = 8080, 30080

	key := UsidVipXlatKey{Block: usid.block, Argument: usid.argument, Proto: 17 /* UDP */, Port: bswap16(vipPort)}
	if err := objs.VipXlatTable.Put(key, UsidVipXlatValue{
		Addr: backend.As16(), Port: bswap16(backendPort),
	}); err != nil {
		t.Fatalf("populate vip_xlat_table: %v", err)
	}

	innerSrc := netip.MustParseAddr("2001:db8:ffff::1")
	const clientPort = 54321
	payload := []byte("hello")

	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], clientPort)
	binary.BigEndian.PutUint16(udp[2:4], vipPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	origCsum := udp6Checksum(innerSrc.As16(), vip.As16(), udp)
	binary.BigEndian.PutUint16(udp[6:8], origCsum)

	pkt := buildPacketWithUDPInner(t, usid.addr(t), netip.MustParseAddr("2001:db8::1"), innerSrc, vip, udp)

	ret, out, err := objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	if got := sumPerCPU(t, objs.DropReasons, DropReasonFibLookupFailed); got != 1 {
		t.Errorf("drop_reasons[fib_lookup_failed] = %d, want 1 (vip_xlat lookup must not have short-circuited)", got)
	}

	const daddrOffset = ethHeaderLen + 24
	const udpOffset = ethHeaderLen + ip6HeaderLen
	var gotDaddr [16]byte
	copy(gotDaddr[:], out[daddrOffset:daddrOffset+16])
	if wantDaddr := backend.As16(); gotDaddr != wantDaddr {
		t.Errorf("daddr after vip_xlat = %x, want %x (backend address)", gotDaddr, wantDaddr)
	}
	gotDstPort := binary.BigEndian.Uint16(out[udpOffset+2 : udpOffset+4])
	if gotDstPort != backendPort {
		t.Errorf("UDP dest port after vip_xlat = %d, want %d", gotDstPort, backendPort)
	}

	gotUDP := out[udpOffset : udpOffset+len(udp)]
	gotCsum := binary.BigEndian.Uint16(gotUDP[6:8])
	udpZeroCsum := append([]byte{}, gotUDP...)
	udpZeroCsum[6], udpZeroCsum[7] = 0, 0
	wantCsum := udp6Checksum(innerSrc.As16(), backend.As16(), udpZeroCsum)
	if gotCsum != wantCsum {
		t.Errorf("UDP checksum after vip_xlat = %#04x, want %#04x (independent full recompute over the "+
			"post-rewrite addr/port) -- apply_vip_xlat's incremental bpf_l4_csum_replace calls produced "+
			"the wrong result", gotCsum, wantCsum)
	}
}

// bswap16 is netip.Addr-adjacent test glue: UsidVipXlatKey/Value's Port
// fields are __be16 (network/big-endian) on the C side; bpf2go generates
// them as a plain uint16 Go field with no automatic byte-swap, so tests
// populating those maps must swap explicitly, matching what usid.c's own
// __builtin_bswap16 calls do to wire-format port values throughout.
func bswap16(v uint16) uint16 { return v<<8 | v>>8 }

// buildPacketWithUDPInner is buildPacketWithV6Addrs's sibling for the
// vip_xlat test above: same outer/inner IPv6 headers, but nexthdr=17 (UDP)
// and udp (a complete, already-checksummed UDP header+payload) appended
// after the inner IPv6 header instead of nothing.
func buildPacketWithUDPInner(t *testing.T, outerDst, outerSrc, innerSrc, innerDst netip.Addr, udp []byte) []byte {
	t.Helper()

	pkt := make([]byte, 0, ethHeaderLen+ip6HeaderLen+ip6HeaderLen+len(udp))
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	pkt = append(pkt, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB)
	pkt = append(pkt, 0x86, 0xDD)

	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	pkt = append(pkt, 0x00, 0x00)
	pkt = append(pkt, 41) // outer nexthdr = IPv6-in-IPv6
	pkt = append(pkt, 64)
	outerSrcBytes := outerSrc.As16()
	pkt = append(pkt, outerSrcBytes[:]...)
	outerDstBytes := outerDst.As16()
	pkt = append(pkt, outerDstBytes[:]...)

	pkt = append(pkt, 0x60, 0x00, 0x00, 0x00)
	payloadLen := uint16(len(udp))
	pkt = append(pkt, byte(payloadLen>>8), byte(payloadLen))
	pkt = append(pkt, 17) // inner nexthdr = UDP
	pkt = append(pkt, 64)
	innerSrcBytes := innerSrc.As16()
	pkt = append(pkt, innerSrcBytes[:]...)
	innerDstBytes := innerDst.As16()
	pkt = append(pkt, innerDstBytes[:]...)
	pkt = append(pkt, udp...)

	return pkt
}

// TestUsidEgress_NoMappingPassesThroughUnmodified covers usid_egress's
// common case (design plan §0.1, §2): most attachments have neither an
// NPTv6 mapping nor an active tap-VIP substitution, and this program must
// never touch their traffic -- TC_ACT_UNSPEC, byte-for-byte unmodified,
// same fail-open contract usid_ingress's own locator-miss path has.
func TestUsidEgress_NoMappingPassesThroughUnmodified(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	pkt := buildPacketWithV6Addrs(t,
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("fd20:60::1"), netip.MustParseAddr("2001:db8:ffff::1"))

	ret, out, err := objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActUnspec {
		t.Errorf("verdict = %d, want TC_ACT_UNSPEC (%d)", ret, tcActUnspec)
	}
	if string(out) != string(pkt) {
		t.Errorf("packet mutated with no ifindex_vrf_table entry:\n in: % x\nout: % x", pkt, out)
	}
}
