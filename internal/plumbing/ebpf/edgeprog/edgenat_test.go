// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	xdpPass = 2
	xdpDrop = 1
	xdpTx   = 3
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN/CAP_SYS_ADMIN) to load BPF programs, create a test " +
			"network namespace, and run BPF_PROG_TEST_RUN against real FIB state; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

// loadObjects loads a fresh copy of the compiled program and its maps into
// the kernel, returning a cleanup-registered *EdgenatObjects.
func loadObjects(t *testing.T) *EdgenatObjects {
	t.Helper()

	var objs EdgenatObjects
	if err := LoadEdgenatObjects(&objs, nil); err != nil {
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

// htons converts a host-order port value into the big-endian byte pattern
// edgenat.c's __be16 fields carry verbatim (the program never byte-swaps a
// port -- every comparison/store is between two equally-unswapped wire
// values) -- so any Go-side value written into a rule_key/conn_key/
// conn_value/backend field mirroring one of those C fields must go through
// this first, on this little-endian test host, or the map key/value the
// program reads will not match what a real client's TCP/IP stack put on
// the wire.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// xdpMDCtx mirrors the kernel UAPI's struct xdp_md field layout (six
// uint32s: data, data_end, data_meta, ingress_ifindex, rx_queue_index,
// egress_ifindex) so it can be passed as ebpf.RunOptions.Context.
// cilium/ebpf's own equivalent (internal/sys.XdpMd) is unexported outside
// its module -- encoding/binary.Append (which Program.Run uses to
// serialize RunOptions.Context) only cares about field layout, not the
// Go type's name, so a local mirror struct with identical field
// order/widths serializes identically.
type xdpMDCtx struct {
	Data           uint32
	DataEnd        uint32
	DataMeta       uint32
	IngressIfindex uint32
	RxQueueIndex   uint32
	EgressIfindex  uint32
}

// runXDP runs prog against pkt with ctx.IngressIfindex set to ifindex, and
// returns the verdict plus whatever this program left in the packet
// buffer -- populated regardless of verdict, so a dropped packet's
// in-progress mutations (e.g. an already-pushed outer header, ahead of a
// FIB lookup failure) can still be inspected.
func runXDP(t *testing.T, prog *ebpf.Program, pkt []byte, ifindex int) (uint32, []byte) {
	t.Helper()
	out := make([]byte, len(pkt)+256) // headroom for adjust_head(-40) growth
	// ctx_in.DataEnd must be set to len(pkt) explicitly -- for
	// BPF_PROG_TEST_RUN, data/data_end in the supplied xdp_md context are
	// offsets into the Data buffer the kernel populates real pointers
	// from, not raw pointers themselves; leaving DataEnd at its zero
	// value gives the program a zero-length packet (confirmed via
	// bpf_trace_printk during development: "entry len=0"), matching
	// cilium/ebpf's own examples/xdp_live_frame, which sets this
	// explicitly for the same reason.
	ret, err := prog.Run(&ebpf.RunOptions{
		Data:    pkt,
		DataOut: out,
		Context: &xdpMDCtx{DataEnd: uint32(len(pkt)), IngressIfindex: uint32(ifindex)},
		Repeat:  1,
	})
	if err != nil {
		t.Fatalf("program run: %v", err)
	}
	return ret, out
}

// testEnv is an isolated network namespace carrying a veth pair with a
// real on-link IPv6 route + static (permanent) neighbor entry for every
// destination address the tests below hand to bpf_fib_lookup, so the
// program's forward/return paths can be proven end-to-end (a real XDP_TX
// with a correctly resolved L2 header), not merely "reached the FIB
// lookup" -- unlike internal/plumbing/ebpf/prog's own tests, which
// explicitly punt on live routing state as a "ContainerLab/e2e concern";
// this package's tests go further because root/kernel access is available
// in this environment and the extra assurance is worth it for the
// centerpiece of this design.
type testEnv struct {
	ifindex int
}

// dummyMAC is an arbitrary, locally-administered MAC address used for
// every static neighbor entry setupTestEnv installs -- its exact value is
// never asserted on by any test (only that *some* resolved dmac/smac made
// it into the rewritten packet, proving bpf_fib_lookup succeeded), so one
// fixed value for every destination is sufficient.
var dummyMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

// setupTestEnv creates a fresh netns, enters it on the calling goroutine's
// OS thread (which is locked for the lifetime of the returned *testEnv --
// call the returned cleanup to unlock and restore the original netns), and
// installs an on-link route + static neighbor entry for every address in
// destinations.
func setupTestEnv(t *testing.T, destinations []netip.Addr) (*testEnv, func()) {
	t.Helper()
	requireRoot(t)

	runtime.LockOSThread()

	origNS, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("netns.Get: %v", err)
	}

	newNS, err := netns.New()
	if err != nil {
		_ = netns.Set(origNS)
		_ = origNS.Close()
		runtime.UnlockOSThread()
		t.Fatalf("netns.New: %v", err)
	}

	cleanup := func() {
		_ = netns.Set(origNS)
		_ = newNS.Close()
		_ = origNS.Close()
		runtime.UnlockOSThread()
	}

	// bpf_fib_lookup returns BPF_FIB_LKUP_RET_FWD_DISABLED unless IPv6
	// forwarding is enabled on the (soon-to-be) ingress device's stack --
	// a fresh network namespace starts with forwarding off, matching the
	// kernel's own default, so this test environment must turn it on
	// explicitly, the same way a real gateway node's sysctl configuration
	// would (see internal/plumbing/sysctl's ConfigureInterfaceSysctls
	// convention for VRF interfaces -- this is the same class of setup).
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644); err != nil {
		cleanup()
		t.Fatalf("enable ipv6 forwarding in test netns: %v", err)
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "edgenat0"},
		PeerName:  "edgenat1",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		cleanup()
		t.Fatalf("create veth pair: %v", err)
	}
	link, err := netlink.LinkByName("edgenat0")
	if err != nil {
		cleanup()
		t.Fatalf("find veth: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		cleanup()
		t.Fatalf("set veth up: %v", err)
	}
	if peer, err := netlink.LinkByName("edgenat1"); err == nil {
		_ = netlink.LinkSetUp(peer)
	}

	// A real address on the link (not itself used as a test destination)
	// so the link has a usable IPv6 scope/source for the routes below.
	addr, err := netlink.ParseAddr("fd00:eda::1/64")
	if err != nil {
		cleanup()
		t.Fatalf("parse veth address: %v", err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		cleanup()
		t.Fatalf("assign veth address: %v", err)
	}

	for _, dst := range destinations {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: dst.AsSlice(), Mask: net.CIDRMask(128, 128)},
		}
		if err := netlink.RouteAdd(route); err != nil {
			cleanup()
			t.Fatalf("add on-link route to %s: %v", dst, err)
		}
		neigh := &netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       unix.AF_INET6,
			State:        netlink.NUD_PERMANENT,
			IP:           dst.AsSlice(),
			HardwareAddr: dummyMAC,
		}
		if err := netlink.NeighAdd(neigh); err != nil {
			cleanup()
			t.Fatalf("add static neighbor for %s: %v", dst, err)
		}
	}

	return &testEnv{ifindex: link.Attrs().Index}, cleanup
}

// ---------------------------------------------------------------------
// Packet construction and checksum verification. edgenat.c's own
// checksum fixups are exercised by these tests via bpf_csum_diff -- this
// section independently recomputes the expected TCP/UDP checksum in Go
// from the rewritten packet's own bytes and compares, the same
// "recompute independently, don't just eyeball it" standard gwprog's
// gwnat_test.go held itself to.
// ---------------------------------------------------------------------

const (
	ethHdrLen = 14
	ip6HdrLen = 40
	tcpHdrLen = 20
	udpHdrLen = 8
)

func sum16(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ipv6L4Checksum computes the RFC 8200 §8.1 pseudo-header + payload
// checksum for an IPv6 TCP/UDP segment. l4 must have its own checksum
// field already zeroed.
func ipv6L4Checksum(src, dst netip.Addr, protocol uint8, l4 []byte) uint16 {
	s, d := src.As16(), dst.As16()
	sum := sum16(s[:]) + sum16(d[:])
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(l4)))
	sum += sum16(lenBuf[:])
	sum += uint32(protocol)
	sum += sum16(l4)
	return foldChecksum(sum)
}

// buildTCPPacket returns a full Ethernet+IPv6+TCP frame (no payload) with
// a correct checksum.
func buildTCPPacket(src, dst netip.Addr, sport, dport uint16, synFlag bool) []byte {
	pkt := make([]byte, ethHdrLen+ip6HdrLen+tcpHdrLen)

	binary.BigEndian.PutUint16(pkt[12:14], 0x86DD) // ethertype IPv6

	ip6 := pkt[ethHdrLen:]
	ip6[0] = 0x60 // version 6, rest of vtc_flow zero
	binary.BigEndian.PutUint16(ip6[4:6], tcpHdrLen)
	ip6[6] = 6 // TCP
	ip6[7] = 64
	sb, db := src.As16(), dst.As16()
	copy(ip6[8:24], sb[:])
	copy(ip6[24:40], db[:])

	tcp := ip6[ip6HdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[13] = 0x10 // ACK
	if synFlag {
		tcp[13] = 0x02 // SYN
	}
	binary.BigEndian.PutUint16(tcp[16:18], 0) // checksum placeholder

	csum := ipv6L4Checksum(src, dst, 6, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], csum)

	return pkt
}

// buildUDPPacket returns a full Ethernet+IPv6+UDP frame (no payload) with
// a correct checksum.
func buildUDPPacket(src, dst netip.Addr, sport, dport uint16) []byte {
	pkt := make([]byte, ethHdrLen+ip6HdrLen+udpHdrLen)

	binary.BigEndian.PutUint16(pkt[12:14], 0x86DD)

	ip6 := pkt[ethHdrLen:]
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], udpHdrLen)
	ip6[6] = 17 // UDP
	ip6[7] = 64
	sb, db := src.As16(), dst.As16()
	copy(ip6[8:24], sb[:])
	copy(ip6[24:40], db[:])

	udp := ip6[ip6HdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], udpHdrLen)
	binary.BigEndian.PutUint16(udp[6:8], 0)

	csum := ipv6L4Checksum(src, dst, 17, udp)
	binary.BigEndian.PutUint16(udp[6:8], csum)

	return pkt
}

// buildEncappedTCPPacket returns an Ethernet+outer-IPv6(NH=41)+inner-IPv6+
// TCP frame -- the wire shape of a return packet arriving at the
// gateway's own SRv6-reachable address, addressed from a backend to the
// gateway's SNAT address:port.
func buildEncappedTCPPacket(
	outerSrc, outerDst, innerSrc, innerDst netip.Addr, sport, dport uint16, synFlag bool,
) []byte {
	inner := buildTCPPacket(innerSrc, innerDst, sport, dport, synFlag)[ethHdrLen:] // strip the throwaway inner eth

	pkt := make([]byte, ethHdrLen+ip6HdrLen+len(inner))
	binary.BigEndian.PutUint16(pkt[12:14], 0x86DD)

	outer := pkt[ethHdrLen:]
	outer[0] = 0x60
	binary.BigEndian.PutUint16(outer[4:6], uint16(len(inner)))
	outer[6] = 41 // IPv6-in-IPv6
	outer[7] = 64
	sb, db := outerSrc.As16(), outerDst.As16()
	copy(outer[8:24], sb[:])
	copy(outer[24:40], db[:])

	copy(pkt[ethHdrLen+ip6HdrLen:], inner)
	return pkt
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%q): %v", s, err)
	}
	return a
}

// Fixed addresses/ports shared across the tests below.
var (
	testVIP        = "2001:db8:1::10"
	testClient     = "2001:db8:99::5"
	testBackendIP  = "fd00:10:1::20"
	testBackendSID = "2001:db8:2::1" // the backend's worker-node SRv6 uSID
	testGWAddr     = "2001:db8:3::1" // this gateway's own SRv6-reachable SNAT address
)

const (
	testVIPPort     = uint16(443)
	testClientPort  = uint16(51234)
	testBackendPort = uint16(8443)
)

// installRule populates rule_table with one VIP/port/protocol rule
// pointing at a single backend, and gw_config_table with this gateway's
// own SRv6 address.
func installRule(t *testing.T, objs *EdgenatObjects) {
	t.Helper()

	vip := mustAddr(t, testVIP).As16()
	backendAddr := mustAddr(t, testBackendIP).As16()
	backendUSID := mustAddr(t, testBackendSID).As16()
	gwAddr := mustAddr(t, testGWAddr).As16()

	rk := EdgenatRuleKey{Proto: 6, Port: htons(testVIPPort), Vip: vip}
	rv := EdgenatRuleValue{BackendCount: 1}
	rv.Backends[0] = EdgenatBackend{Addr: backendAddr, Port: htons(testBackendPort), Usid: backendUSID}
	if err := objs.RuleTable.Put(rk, rv); err != nil {
		t.Fatalf("populate rule_table: %v", err)
	}

	if err := objs.GwConfigTable.Put(uint32(0), EdgenatGwConfig{GwAddr: gwAddr}); err != nil {
		t.Fatalf("populate gw_config_table: %v", err)
	}
}

func parseEth(t *testing.T, pkt []byte) {
	t.Helper()
	if len(pkt) < ethHdrLen {
		t.Fatalf("packet too short for an Ethernet header: %d bytes", len(pkt))
	}
	if got := binary.BigEndian.Uint16(pkt[12:14]); got != 0x86DD {
		t.Errorf("ethertype = %#04x, want 0x86dd (IPv6)", got)
	}
}

// TestEdgeNat_NoRuleMatchPassesThrough covers a TCP packet to an address
// with no rule_table entry at all -- must XDP_PASS untouched, so ordinary
// traffic to the node itself (SSH, BGP) is never affected.
func TestEdgeNat_NoRuleMatchPassesThrough(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	pkt := buildTCPPacket(mustAddr(t, testClient), mustAddr(t, "2001:db8:1::99"), testClientPort, 22, true)
	ret, out := runXDP(t, objs.EdgeNat, pkt, 1)
	if ret != xdpPass {
		t.Fatalf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
	if string(out[:len(pkt)]) != string(pkt) {
		t.Error("XDP_PASS packet was modified, want byte-for-byte untouched")
	}
}

// TestEdgeNat_ForwardSYNAllocatesRewritesAndEncapsulates covers the full
// forward path end-to-end: a fresh SYN to a known VIP must be DNAT'd to
// the backend, SNAT'd to this gateway's own address, checksum-fixed, and
// wrapped in a correctly addressed outer SRv6 header, with a real
// bpf_fib_lookup-resolved L2 header (proven via the on-link route/neighbor
// this test's testEnv installs) -- ending in XDP_TX, not just "reached
// the FIB lookup."
func TestEdgeNat_ForwardSYNAllocatesRewritesAndEncapsulates(t *testing.T) {
	env, cleanup := setupTestEnv(t, []netip.Addr{mustAddr(t, testBackendSID)})
	defer cleanup()

	objs := loadObjects(t)
	installRule(t, objs)

	pkt := buildTCPPacket(mustAddr(t, testClient), mustAddr(t, testVIP), testClientPort, testVIPPort, true)
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
	if got := netip.AddrFrom16([16]byte(outer[8:24])); got != mustAddr(t, testGWAddr) {
		t.Errorf("outer saddr = %s, want this gateway's own address %s", got, testGWAddr)
	}
	if got := netip.AddrFrom16([16]byte(outer[24:40])); got != mustAddr(t, testBackendSID) {
		t.Errorf("outer daddr = %s, want the backend's worker-node uSID %s", got, testBackendSID)
	}

	inner := outer[ip6HdrLen:]
	if got := netip.AddrFrom16([16]byte(inner[8:24])); got != mustAddr(t, testGWAddr) {
		t.Errorf("inner saddr (SNAT) = %s, want gateway address %s", got, testGWAddr)
	}
	if got := netip.AddrFrom16([16]byte(inner[24:40])); got != mustAddr(t, testBackendIP) {
		t.Errorf("inner daddr (DNAT) = %s, want backend address %s", got, testBackendIP)
	}

	tcp := inner[ip6HdrLen:]
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != testBackendPort {
		t.Errorf("inner dest port = %d, want backend port %d", got, testBackendPort)
	}
	gotSNATPort := binary.BigEndian.Uint16(tcp[0:2])

	wantCsum := ipv6L4ChecksumZeroed(t, mustAddr(t, testGWAddr), mustAddr(t, testBackendIP), 6, tcp)
	if gotCsum := binary.BigEndian.Uint16(tcp[16:18]); gotCsum != wantCsum {
		t.Errorf("inner TCP checksum = %#04x, want %#04x (independently recomputed)", gotCsum, wantCsum)
	}

	// A second packet on the same 5-tuple (even a plain ACK, not a SYN)
	// must reuse the exact same backend/SNAT-port assignment via
	// conn_table, not drop or re-allocate.
	pkt2 := buildTCPPacket(mustAddr(t, testClient), mustAddr(t, testVIP), testClientPort, testVIPPort, false)
	ret2, out2 := runXDP(t, objs.EdgeNat, pkt2, env.ifindex)
	if ret2 != xdpTx {
		t.Fatalf("second packet verdict = %d, want XDP_TX (%d)", ret2, xdpTx)
	}
	out2 = out2[:wantLen]
	inner2 := out2[ethHdrLen+ip6HdrLen+ip6HdrLen:]
	if got := binary.BigEndian.Uint16(inner2[0:2]); got != gotSNATPort {
		t.Errorf("second packet SNAT port = %d, want the same allocated port %d (reused from conn_table)",
			got, gotSNATPort)
	}
}

// TestEdgeNat_ForwardIncrementsRuleHitCounters covers the design plan's
// Phase E hit counters: a successfully forwarded packet must bump
// rule_table's Packets/Bytes/LastSeenNs (backing internal/gateway's
// QuotaEnforcer/TelemetryEmitter), with DroppedPackets left at zero since
// nothing was dropped.
func TestEdgeNat_ForwardIncrementsRuleHitCounters(t *testing.T) {
	env, cleanup := setupTestEnv(t, []netip.Addr{mustAddr(t, testBackendSID)})
	defer cleanup()

	objs := loadObjects(t)
	installRule(t, objs)

	pkt := buildTCPPacket(mustAddr(t, testClient), mustAddr(t, testVIP), testClientPort, testVIPPort, true)
	ret, _ := runXDP(t, objs.EdgeNat, pkt, env.ifindex)
	if ret != xdpTx {
		t.Fatalf("verdict = %d, want XDP_TX (%d)", ret, xdpTx)
	}

	rk := EdgenatRuleKey{Proto: 6, Port: htons(testVIPPort), Vip: mustAddr(t, testVIP).As16()}
	var rv EdgenatRuleValue
	if err := objs.RuleTable.Lookup(rk, &rv); err != nil {
		t.Fatalf("read back rule_table entry: %v", err)
	}
	if rv.Packets != 1 {
		t.Errorf("rule_table Packets = %d, want 1", rv.Packets)
	}
	if rv.Bytes != uint64(len(pkt)) {
		t.Errorf("rule_table Bytes = %d, want %d (the ingress packet's own length)", rv.Bytes, len(pkt))
	}
	if rv.DroppedPackets != 0 {
		t.Errorf("rule_table DroppedPackets = %d, want 0 (nothing was dropped)", rv.DroppedPackets)
	}
	if rv.LastSeenNs == 0 {
		t.Error("rule_table LastSeenNs was never stamped")
	}

	// A second packet on the same flow must add to Packets/Bytes, not
	// reset them -- edgemap.RuleTable.Register's read-modify-write must
	// preserve these across re-registration too (see ruletable_test.go),
	// but this confirms the datapath side accumulates correctly first.
	pkt2 := buildTCPPacket(mustAddr(t, testClient), mustAddr(t, testVIP), testClientPort, testVIPPort, false)
	if ret2, _ := runXDP(t, objs.EdgeNat, pkt2, env.ifindex); ret2 != xdpTx {
		t.Fatalf("second packet verdict = %d, want XDP_TX (%d)", ret2, xdpTx)
	}
	var rv2 EdgenatRuleValue
	if err := objs.RuleTable.Lookup(rk, &rv2); err != nil {
		t.Fatalf("read back rule_table entry after second packet: %v", err)
	}
	if rv2.Packets != 2 {
		t.Errorf("rule_table Packets after second packet = %d, want 2 (accumulated, not reset)", rv2.Packets)
	}
	if rv2.Bytes != rv.Bytes+uint64(len(pkt2)) {
		t.Errorf("rule_table Bytes after second packet = %d, want %d (accumulated)", rv2.Bytes, rv.Bytes+uint64(len(pkt2)))
	}
}

// TestEdgeNat_ForwardNonSYNWithNoConnDrops covers a non-SYN TCP packet
// (an ACK, say) to a known VIP with no existing conn_table state -- there
// is no correct point to start a brand-new translated flow except a SYN
// (or, for UDP, any first packet), so this must drop, not pass through
// (the VIP is claimed).
func TestEdgeNat_ForwardNonSYNWithNoConnDrops(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	installRule(t, objs)

	pkt := buildTCPPacket(mustAddr(t, testClient), mustAddr(t, testVIP), testClientPort, testVIPPort, false)
	ret, _ := runXDP(t, objs.EdgeNat, pkt, 1)
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}

	got := sumPerCPU(t, objs.DropReasons, DropReasonNoConnNotSyn)
	if got != 1 {
		t.Errorf("drop_reasons[no_conn_not_syn] = %d, want 1", got)
	}

	// The drop happened after this packet's VIP+port+protocol matched
	// rule_table (design plan Phase E), so it counts against both the
	// rule's own Packets (every packet that matched, regardless of
	// outcome) and DroppedPackets (the claimed-drop subset) -- see
	// edgenat.c's count_claimed_drop.
	rk := EdgenatRuleKey{Proto: 6, Port: htons(testVIPPort), Vip: mustAddr(t, testVIP).As16()}
	var rv EdgenatRuleValue
	if err := objs.RuleTable.Lookup(rk, &rv); err != nil {
		t.Fatalf("read back rule_table entry: %v", err)
	}
	if rv.Packets != 1 {
		t.Errorf("rule_table Packets = %d, want 1", rv.Packets)
	}
	if rv.DroppedPackets != 1 {
		t.Errorf("rule_table DroppedPackets = %d, want 1", rv.DroppedPackets)
	}
	if rv.LastSeenNs == 0 {
		t.Error("rule_table LastSeenNs was never stamped")
	}
}

// TestEdgeNat_ForwardUDPFirstPacketAllocates covers the UDP path: unlike
// TCP, any first packet (no SYN concept) may start a new flow.
func TestEdgeNat_ForwardUDPFirstPacketAllocates(t *testing.T) {
	env, cleanup := setupTestEnv(t, []netip.Addr{mustAddr(t, testBackendSID)})
	defer cleanup()

	objs := loadObjects(t)
	vip := mustAddr(t, testVIP).As16()
	backendAddr := mustAddr(t, testBackendIP).As16()
	backendUSID := mustAddr(t, testBackendSID).As16()
	gwAddr := mustAddr(t, testGWAddr).As16()

	rk := EdgenatRuleKey{Proto: 17, Port: htons(53), Vip: vip}
	rv := EdgenatRuleValue{BackendCount: 1}
	rv.Backends[0] = EdgenatBackend{Addr: backendAddr, Port: htons(testBackendPort), Usid: backendUSID}
	if err := objs.RuleTable.Put(rk, rv); err != nil {
		t.Fatalf("populate rule_table: %v", err)
	}
	if err := objs.GwConfigTable.Put(uint32(0), EdgenatGwConfig{GwAddr: gwAddr}); err != nil {
		t.Fatalf("populate gw_config_table: %v", err)
	}

	pkt := buildUDPPacket(mustAddr(t, testClient), mustAddr(t, testVIP), testClientPort, 53)
	ret, _ := runXDP(t, objs.EdgeNat, pkt, env.ifindex)
	if ret != xdpTx {
		t.Fatalf("verdict = %d, want XDP_TX (%d)", ret, xdpTx)
	}
}

// TestEdgeNat_ReturnPacketUnNATsEndToEnd covers the return/decap branch:
// a reply from the backend, encapsulated and addressed to this gateway's
// own SRv6 address, must be decapsulated, un-SNAT'd/un-DNAT'd back to the
// client's original view, checksum-fixed, and transmitted toward the
// client with a real FIB-resolved L2 header.
func TestEdgeNat_ReturnPacketUnNATsEndToEnd(t *testing.T) {
	env, cleanup := setupTestEnv(t, []netip.Addr{mustAddr(t, testClient)})
	defer cleanup()

	objs := loadObjects(t)

	gwAddr := mustAddr(t, testGWAddr)
	if err := objs.GwConfigTable.Put(uint32(0), EdgenatGwConfig{GwAddr: gwAddr.As16()}); err != nil {
		t.Fatalf("populate gw_config_table: %v", err)
	}

	const snatPort = uint16(40000)
	rev := EdgenatConnKey{
		Proto: 6,
		Saddr: mustAddr(t, testBackendIP).As16(),
		Sport: htons(testBackendPort),
		Daddr: gwAddr.As16(),
		Dport: htons(snatPort),
	}
	cv := EdgenatConnValue{
		ClientAddr:  mustAddr(t, testClient).As16(),
		ClientPort:  htons(testClientPort),
		VipAddr:     mustAddr(t, testVIP).As16(),
		VipPort:     htons(testVIPPort),
		BackendAddr: mustAddr(t, testBackendIP).As16(),
		BackendPort: htons(testBackendPort),
		BackendUsid: mustAddr(t, testBackendSID).As16(),
		GwAddr:      gwAddr.As16(),
		GwPort:      htons(snatPort),
		Proto:       6,
	}
	if err := objs.ConnTable.Put(rev, cv); err != nil {
		t.Fatalf("populate conn_table reverse row: %v", err)
	}

	// buildEncappedTCPPacket (like buildTCPPacket, which it wraps) takes
	// host-order port arguments and does its own big-endian encoding --
	// snatPort is already a plain host-order value, matching testBackendPort.
	pkt := buildEncappedTCPPacket(
		mustAddr(t, testBackendSID), gwAddr,
		mustAddr(t, testBackendIP), gwAddr,
		testBackendPort, snatPort, false,
	)

	ret, out := runXDP(t, objs.EdgeNat, pkt, env.ifindex)
	if ret != xdpTx {
		t.Fatalf("verdict = %d, want XDP_TX (%d)", ret, xdpTx)
	}

	wantLen := ethHdrLen + ip6HdrLen + tcpHdrLen
	out = out[:wantLen]
	parseEth(t, out)

	ip6 := out[ethHdrLen:]
	if got := netip.AddrFrom16([16]byte(ip6[8:24])); got != mustAddr(t, testVIP) {
		t.Errorf("saddr (un-DNAT) = %s, want VIP %s", got, testVIP)
	}
	if got := netip.AddrFrom16([16]byte(ip6[24:40])); got != mustAddr(t, testClient) {
		t.Errorf("daddr (un-SNAT) = %s, want client %s", got, testClient)
	}

	tcp := ip6[ip6HdrLen:]
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != testVIPPort {
		t.Errorf("source port = %d, want VIP port %d", got, testVIPPort)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != testClientPort {
		t.Errorf("dest port = %d, want client port %d", got, testClientPort)
	}

	wantCsum := ipv6L4ChecksumZeroed(t, mustAddr(t, testVIP), mustAddr(t, testClient), 6, tcp)
	if gotCsum := binary.BigEndian.Uint16(tcp[16:18]); gotCsum != wantCsum {
		t.Errorf("TCP checksum = %#04x, want %#04x (independently recomputed)", gotCsum, wantCsum)
	}
}

// TestEdgeNat_ReturnWithNoConnDrops covers a packet addressed to this
// gateway's own SRv6 address with no matching conn_table row -- the
// address is claimed, so this must drop, not pass through.
func TestEdgeNat_ReturnWithNoConnDrops(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	gwAddr := mustAddr(t, testGWAddr)
	if err := objs.GwConfigTable.Put(uint32(0), EdgenatGwConfig{GwAddr: gwAddr.As16()}); err != nil {
		t.Fatalf("populate gw_config_table: %v", err)
	}

	pkt := buildEncappedTCPPacket(
		mustAddr(t, testBackendSID), gwAddr,
		mustAddr(t, testBackendIP), gwAddr,
		testBackendPort, 40000, false,
	)
	ret, _ := runXDP(t, objs.EdgeNat, pkt, 1)
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}

	got := sumPerCPU(t, objs.DropReasons, DropReasonNoReturnConn)
	if got != 1 {
		t.Errorf("drop_reasons[no_return_conn] = %d, want 1", got)
	}
}

// ipv6L4ChecksumZeroed recomputes the expected checksum for l4 (whose own
// checksum field is NOT already zero) by zeroing a copy of that field
// first, matching how a real TCP/IP stack computes it.
func ipv6L4ChecksumZeroed(t *testing.T, src, dst netip.Addr, protocol uint8, l4 []byte) uint16 {
	t.Helper()
	cp := make([]byte, len(l4))
	copy(cp, l4)
	binary.BigEndian.PutUint16(cp[16:18], 0)
	return ipv6L4Checksum(src, dst, protocol, cp)
}

// sumPerCPU sums a BPF_MAP_TYPE_PERCPU_ARRAY counter across every CPU.
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
