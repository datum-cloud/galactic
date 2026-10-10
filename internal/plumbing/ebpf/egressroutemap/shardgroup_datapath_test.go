// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"go.datum.net/galactic/internal/maglev"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// These tests run usid_egress under BPF_PROG_RUN against maps written by the
// Go group API, so the datapath's hash, Maglev lookup, pin handling and SID
// completion are checked against what the control plane wrote rather than
// against hand-built map values.

const (
	tcActShot     = 2
	tcActRedirect = 7

	dpTableID  = 42
	dpBlock    = 0x0102030405AA
	dpArgument = 0x2A5
	ethLen     = 14
	ip6Len     = 40
)

var (
	dpShardMAC  = net.HardwareAddr{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01}
	dpUplinkMAC = net.HardwareAddr{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02}
)

// datapath is one loaded usid program with an attachment on ifindex 1, the
// skb->ifindex BPF_PROG_RUN uses, whose VRF's ::/0 names the cluster group.
type datapath struct {
	objs   *prog.UsidObjects
	store  *KernelGroupStore
	groups *ShardGroupTable
	routes *EgressRouteTable
}

func loadDatapath(t *testing.T) *datapath {
	t.Helper()
	requireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}

	var objs prog.UsidObjects
	if err := prog.LoadUsidObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load objects: verifier rejected program:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	attachment := prog.UsidIfindexVrfValue{Block: dpBlock, Argument: dpArgument}
	if err := objs.IfindexVrfTable.Put(uint32(1), attachment); err != nil {
		t.Fatalf("populate ifindex_vrf_table: %v", err)
	}
	vrfKey, err := uformat.NewVRFKey(dpBlock, dpArgument)
	if err != nil {
		t.Fatalf("NewVRFKey: %v", err)
	}
	if err := objs.VrfTable.Put(uint64(vrfKey), prog.UsidVrfValue{VrfTableId: dpTableID}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
	nodeSrc := netip.MustParseAddr("2001:db8:ff01:1:e000::").As16()
	if err := objs.NodeSrcAddrTable.Put(uint32(0), nodeSrc); err != nil {
		t.Fatalf("populate node_src_addr_table: %v", err)
	}

	dp := &datapath{
		objs:   &objs,
		store:  NewKernelGroupStore(objs.EgressShardGroups),
		routes: NewEgressRouteTable(usidmap.KernelTable{Map: objs.EgressRouteTable}),
	}
	dp.groups = NewShardGroupTable(dp.store)
	if err := dp.routes.RegisterGroup(dpTableID, DefaultPrefix, NAT66ShardGroup, dpArgument); err != nil {
		t.Fatalf("RegisterGroup(::/0): %v", err)
	}
	_, v4Default, _ := net.ParseCIDR("0.0.0.0/0")
	if err := dp.routes.RegisterGroup(dpTableID, v4Default, NAT66ShardGroup, dpArgument); err != nil {
		t.Fatalf("RegisterGroup(0.0.0.0/0): %v", err)
	}
	return dp
}

// reachable stubs the resolver so every SID in alive resolves out ifindex 1
// and every other SID fails.
func reachable(t *testing.T, alive ...netip.Addr) {
	t.Helper()
	ok := map[netip.Addr]bool{}
	for _, a := range alive {
		ok[a] = true
	}
	prev := resolveLinkAndL2Fn
	resolveLinkAndL2Fn = func(sid net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		addr, _ := netip.AddrFromSlice(sid)
		if !ok[addr.Unmap()] {
			return 0, nil, nil, errors.New("unreachable in this test")
		}
		return 1, dpShardMAC, dpUplinkMAC, nil
	}
	t.Cleanup(func() { resolveLinkAndL2Fn = prev })
}

func shardSID(nodeID uint16) netip.Addr {
	addr, err := uformat.Encode(uformat.Fields{Block: 0x20010db8ff09, NodeID: nodeID, Function: uformat.FunctionEndDT46})
	if err != nil {
		panic(err)
	}
	return addr
}

func candidates(draining map[netip.Addr]bool, sids ...netip.Addr) []ShardCandidate {
	out := make([]ShardCandidate, 0, len(sids))
	for _, s := range sids {
		out = append(out, ShardCandidate{SID: net.IP(s.AsSlice()), Draining: draining[s]})
	}
	return out
}

func (dp *datapath) apply(t *testing.T, policy GroupPolicy, c []ShardCandidate) GroupResult {
	t.Helper()
	result, err := dp.groups.Apply(NAT66ShardGroup, policy, c)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return result
}

// udp6 builds Ethernet + IPv6 + UDP from src:sport to dst:dport.
func udp6(src, dst netip.Addr, sport, dport uint16) []byte {
	pkt := make([]byte, 0, ethLen+ip6Len+8)
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x86, 0xDD)
	pkt = append(pkt, 0x60, 0, 0, 0, 0, 8, 17, 64)
	s, d := src.As16(), dst.As16()
	pkt = append(pkt, s[:]...)
	pkt = append(pkt, d[:]...)
	pkt = binary.BigEndian.AppendUint16(pkt, sport)
	pkt = binary.BigEndian.AppendUint16(pkt, dport)
	pkt = append(pkt, 0, 8, 0, 0)
	return pkt
}

// udp4 builds Ethernet + IPv4 + UDP, with fragOff as the raw frag_off field.
func udp4(src, dst netip.Addr, sport, dport, fragOff uint16) []byte {
	pkt := make([]byte, 0, ethLen+20+8)
	pkt = append(pkt, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x08, 0x00)
	pkt = append(pkt, 0x45, 0, 0, 28, 0, 0)
	pkt = binary.BigEndian.AppendUint16(pkt, fragOff)
	pkt = append(pkt, 64, 17, 0, 0)
	s, d := src.As4(), dst.As4()
	pkt = append(pkt, s[:]...)
	pkt = append(pkt, d[:]...)
	pkt = binary.BigEndian.AppendUint16(pkt, sport)
	pkt = binary.BigEndian.AppendUint16(pkt, dport)
	pkt = append(pkt, 0, 8, 0, 0)
	return pkt
}

// send runs pkt through usid_egress and returns the verdict and, for a
// redirect, the outer destination with its Argument cleared, plus the
// Argument it carried.
func (dp *datapath) send(t *testing.T, pkt []byte) (verdict uint32, shard netip.Addr, argument uint16) {
	t.Helper()
	ret, out, err := dp.objs.UsidEgress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActRedirect {
		return ret, netip.Addr{}, 0
	}
	if len(out) != len(pkt)+ip6Len {
		t.Fatalf("output length %d, want %d", len(out), len(pkt)+ip6Len)
	}
	if got := net.HardwareAddr(out[0:6]); got.String() != dpShardMAC.String() {
		t.Errorf("outer h_dest = %s, want the shard's resolved %s", got, dpShardMAC)
	}
	dst, _ := netip.AddrFromSlice(out[ethLen+24 : ethLen+40])
	fields, err := uformat.Decode(dst)
	if err != nil {
		t.Fatalf("outer destination %s is not a uSID: %v", dst, err)
	}
	argument = fields.Argument
	fields.Argument = 0
	base, _ := uformat.Encode(fields)
	return ret, base, argument
}

// predict is the shard the Go side expects the datapath to choose for key
// with no pin: the Maglev table built over active, indexed by ShardHash.
func predict(t *testing.T, key ShardPinKey, mode HashMode, active ...netip.Addr) netip.Addr {
	t.Helper()
	backends := make([]maglev.Backend, 0, len(active))
	for i, a := range active {
		backends = append(backends, shardBackend{sid: a, slot: i})
	}
	table, err := maglev.New(backends, ShardMaglevTableSize)
	if err != nil {
		t.Fatalf("maglev.New: %v", err)
	}
	return table.Lookup(uint64(ShardHash(key.Bytes(mode)))).(shardBackend).sid
}

func tenant(i int) netip.Addr {
	a := netip.MustParseAddr("2001:db8:aaaa::").As16()
	binary.BigEndian.PutUint16(a[14:16], uint16(i)) //nolint:gosec // test index
	return netip.AddrFrom16(a)
}

var internet = netip.MustParseAddr("2001:db8:ffff::1")

func stat(t *testing.T, m *ebpf.Map, index uint32) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := m.Lookup(index, &perCPU); err != nil {
		t.Fatalf("lookup stat %d: %v", index, err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// TestGroupDatapath_SourceHashMatchesGoAndSpreadsEvenly checks that every
// tenant address goes where the Go side predicts, that the tenant's Argument
// is written into the chosen shard's SID, and that three shards each carry
// close to a third of 600 addresses.
func TestGroupDatapath_SourceHashMatchesGoAndSpreadsEvenly(t *testing.T) {
	dp := loadDatapath(t)
	a, b, c := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachable(t, a, b, c)
	dp.apply(t, GroupPolicy{}, candidates(nil, a, b, c))

	share := map[netip.Addr]int{}
	for i := range 600 {
		src := tenant(i)
		verdict, shard, argument := dp.send(t, udp6(src, internet, uint16(1000+i), 443)) //nolint:gosec // test index
		if verdict != tcActRedirect {
			t.Fatalf("tenant %s: verdict %d, want redirect", src, verdict)
		}
		if argument != dpArgument {
			t.Fatalf("tenant %s: outer SID Argument %#x, want the VRF's %#x", src, argument, dpArgument)
		}
		want := predict(t, ShardPinKey{TableID: dpTableID, Src: src}, HashSource, a, b, c)
		if shard != want {
			t.Fatalf("tenant %s: datapath chose %s, Go predicts %s", src, shard, want)
		}
		share[shard]++
	}
	for _, s := range []netip.Addr{a, b, c} {
		if share[s] < 150 || share[s] > 250 {
			t.Errorf("shard %s carried %d of 600 tenant addresses, want close to 200 (shares %v)", s, share[s], share)
		}
	}

	// The same address keeps its shard whatever its ports: paired pooling.
	for port := range uint16(20) {
		_, shard, _ := dp.send(t, udp6(tenant(7), internet, 2000+port, 80+port))
		if want := predict(t, ShardPinKey{TableID: dpTableID, Src: tenant(7)}, HashSource, a, b, c); shard != want {
			t.Fatalf("tenant %s port %d moved to %s, want %s for every flow", tenant(7), 2000+port, shard, want)
		}
	}

	var counters []prog.UsidEgressShardCounter
	var counted uint64
	for slot := range 3 {
		if err := dp.objs.EgressShardCounters.Lookup(uint32(slot), &counters); err != nil { //nolint:gosec // < 3
			t.Fatalf("lookup egress_shard_counters[%d]: %v", slot, err)
		}
		for _, v := range counters {
			counted += v.Packets
		}
	}
	if counted != 620 {
		t.Errorf("egress_shard_counters total %d packets, want 620", counted)
	}
	if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatMaglev); got != 620 {
		t.Errorf("egress_shard_stats[maglev] = %d, want 620", got)
	}
}

// TestGroupDatapath_FailureMovesOnlyTheFailedShardsTenants checks Maglev's
// stability through the whole stack: when one of three shards stops
// resolving, only the addresses it carried move.
func TestGroupDatapath_FailureMovesOnlyTheFailedShardsTenants(t *testing.T) {
	dp := loadDatapath(t)
	a, b, c := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachable(t, a, b, c)
	dp.apply(t, GroupPolicy{}, candidates(nil, a, b, c))

	before := map[int]netip.Addr{}
	for i := range 300 {
		_, before[i], _ = dp.send(t, udp6(tenant(i), internet, 5000, 443))
	}

	reachable(t, a, c) // b's route is withdrawn
	result := dp.apply(t, GroupPolicy{}, candidates(nil, a, b, c))
	if result.Active() != 2 {
		t.Fatalf("Apply active = %d, want 2", result.Active())
	}
	// Maglev bounds disruption rather than eliminating it: a few slots of
	// the surviving shards are reassigned as the table refills. Allow 5%.
	var survivors, moved int
	for i := range 300 {
		verdict, after, _ := dp.send(t, udp6(tenant(i), internet, 5000, 443))
		if verdict != tcActRedirect {
			t.Fatalf("tenant %d: verdict %d after b failed, want redirect", i, verdict)
		}
		if after == b {
			t.Fatalf("tenant %d still sent to unreachable shard %s", i, b)
		}
		if before[i] != b {
			survivors++
			if after != before[i] {
				moved++
			}
		}
	}
	if moved*20 > survivors {
		t.Errorf("%d of %d tenants on surviving shards moved, want at most 5%%", moved, survivors)
	}
}

// TestGroupDatapath_PinsHoldThroughAddAndDrain checks Phase 3: a tenant
// address pinned to a shard stays there when a new shard joins and when its
// shard drains, and moves only once its shard becomes unreachable.
func TestGroupDatapath_PinsHoldThroughAddAndDrain(t *testing.T) {
	dp := loadDatapath(t)
	a, b, c := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachable(t, a, b, c)
	policy := GroupPolicy{PinIdle: time.Hour}
	dp.apply(t, policy, candidates(nil, a, b))

	// Find a tenant that Maglev would move to c once c joins.
	var mover netip.Addr
	var pinnedTo netip.Addr
	for i := range 1000 {
		key := ShardPinKey{TableID: dpTableID, Src: tenant(i)}
		if predict(t, key, HashSource, a, b, c) == c {
			mover, pinnedTo = tenant(i), predict(t, key, HashSource, a, b)
			break
		}
	}
	if !mover.IsValid() {
		t.Fatal("no tenant address in 1000 hashes to the new shard")
	}
	if _, got, _ := dp.send(t, udp6(mover, internet, 1, 1)); got != pinnedTo {
		t.Fatalf("first packet went to %s, want %s", got, pinnedTo)
	}

	dp.apply(t, policy, candidates(nil, a, b, c))
	if _, got, _ := dp.send(t, udp6(mover, internet, 2, 2)); got != pinnedTo {
		t.Errorf("after c joined, pinned tenant went to %s, want its pinned %s", got, pinnedTo)
	}
	// A new tenant address that hashes to c does go there.
	if _, got, _ := dp.send(t, udp6(mover.Next(), internet, 1, 1)); got != predict(t,
		ShardPinKey{TableID: dpTableID, Src: mover.Next()}, HashSource, a, b, c) {
		t.Errorf("an unpinned tenant was not placed by the new table")
	}

	dp.apply(t, policy, candidates(map[netip.Addr]bool{pinnedTo: true}, a, b, c))
	if _, got, _ := dp.send(t, udp6(mover, internet, 3, 3)); got != pinnedTo {
		t.Errorf("after %s began draining, pinned tenant went to %s, want it kept there", pinnedTo, got)
	}
	// Nothing new is placed on the draining shard.
	for i := 1000; i < 1300; i++ {
		if _, got, _ := dp.send(t, udp6(tenant(i), internet, 1, 1)); got == pinnedTo {
			t.Fatalf("new tenant %s placed on draining shard %s", tenant(i), pinnedTo)
		}
	}
	if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatPinHit); got != 2 {
		t.Errorf("egress_shard_stats[pin_hit] = %d, want 2", got)
	}

	var others []netip.Addr
	for _, s := range []netip.Addr{a, b, c} {
		if s != pinnedTo {
			others = append(others, s)
		}
	}
	reachable(t, others...)
	dp.apply(t, policy, candidates(map[netip.Addr]bool{pinnedTo: true}, a, b, c))
	if _, got, _ := dp.send(t, udp6(mover, internet, 4, 4)); got == pinnedTo || !got.IsValid() {
		t.Errorf("after %s became unreachable, pinned tenant went to %s, want another shard", pinnedTo, got)
	}
	if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatPinStale); got != 1 {
		t.Errorf("egress_shard_stats[pin_stale] = %d, want 1", got)
	}
}

// TestGroupDatapath_SlotReuseDoesNotInheritPins checks that a slot handed to
// a different shard does not honour the previous occupant's pins.
func TestGroupDatapath_SlotReuseDoesNotInheritPins(t *testing.T) {
	dp := loadDatapath(t)
	a, b := shardSID(0x10), shardSID(0x11)
	reachable(t, a, b)
	policy := GroupPolicy{PinIdle: time.Hour}
	dp.apply(t, policy, candidates(nil, a))
	if _, got, _ := dp.send(t, udp6(tenant(1), internet, 1, 1)); got != a {
		t.Fatalf("only shard is %s, packet went to %s", a, got)
	}

	// a leaves and b takes slot 0.
	result := dp.apply(t, policy, candidates(nil, b))
	if result.Shards[0].Slot != 0 || !result.Shards[0].Assigned {
		t.Fatalf("b got slot %d (assigned %v), want slot 0 newly assigned", result.Shards[0].Slot, result.Shards[0].Assigned)
	}
	if _, got, _ := dp.send(t, udp6(tenant(1), internet, 1, 1)); got != b {
		t.Errorf("packet went to %s, want %s", got, b)
	}
	if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatPinStale); got != 1 {
		t.Errorf("egress_shard_stats[pin_stale] = %d, want 1: the old pin must be rejected by generation", got)
	}
}

// TestGroupDatapath_EmptyOrDisabledGroupDrops checks that a sentinel never
// fails open.
func TestGroupDatapath_EmptyOrDisabledGroupDrops(t *testing.T) {
	dp := loadDatapath(t)
	a := shardSID(0x10)
	pkt := udp6(tenant(1), internet, 1, 1)

	if verdict, _, _ := dp.send(t, pkt); verdict != tcActShot {
		t.Errorf("never-applied group: verdict %d, want TC_ACT_SHOT", verdict)
	}

	reachable(t) // nothing resolves
	dp.apply(t, GroupPolicy{}, candidates(nil, a))
	if verdict, _, _ := dp.send(t, pkt); verdict != tcActShot {
		t.Errorf("group with no reachable shard: verdict %d, want TC_ACT_SHOT", verdict)
	}

	reachable(t, a)
	dp.apply(t, GroupPolicy{}, candidates(nil, a))
	if verdict, _, _ := dp.send(t, pkt); verdict != tcActRedirect {
		t.Errorf("group with a reachable shard: verdict %d, want redirect", verdict)
	}

	if _, err := dp.groups.Disable(NAT66ShardGroup); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if verdict, _, _ := dp.send(t, pkt); verdict != tcActShot {
		t.Errorf("disabled group: verdict %d, want TC_ACT_SHOT", verdict)
	}
	if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatGroupEmpty); got != 3 {
		t.Errorf("egress_shard_stats[group_empty] = %d, want 3", got)
	}
}

// TestGroupDatapath_FlowHashSpreadsOneAddress checks Phase 4's flow mode: one
// tenant address reaches more than one shard, every packet of one flow
// reaches one, and IPv4 fragments of one datagram stay together.
func TestGroupDatapath_FlowHashSpreadsOneAddress(t *testing.T) {
	dp := loadDatapath(t)
	a, b, c := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachable(t, a, b, c)
	dp.apply(t, GroupPolicy{Hash: HashFlow}, candidates(nil, a, b, c))

	used := map[netip.Addr]bool{}
	for port := range uint16(60) {
		src := tenant(1)
		_, got, _ := dp.send(t, udp6(src, internet, 3000+port, 443))
		want := predict(t, ShardPinKey{
			TableID: dpTableID, Src: src, Dst: internet, Protocol: 17, SrcPort: 3000 + port, DstPort: 443,
		}, HashFlow, a, b, c)
		if got != want {
			t.Fatalf("flow from port %d went to %s, Go predicts %s", 3000+port, got, want)
		}
		used[got] = true
	}
	if len(used) != 3 {
		t.Errorf("60 flows from one address used %d shards, want all 3", len(used))
	}

	src4, dst4 := netip.MustParseAddr("10.0.0.7"), netip.MustParseAddr("192.0.2.9")
	const moreFragments, offset = 0x2000, 0x00B9
	_, first, _ := dp.send(t, udp4(src4, dst4, 4000, 53, moreFragments))
	_, later, _ := dp.send(t, udp4(src4, dst4, 0, 0, offset))
	if first != later {
		t.Errorf("IPv4 fragments of one datagram went to %s and %s, want one shard", first, later)
	}
	want := predict(t, ShardPinKey{TableID: dpTableID, Src: src4, Dst: dst4, Protocol: 17}, HashFlow, a, b, c)
	if first != want {
		t.Errorf("first fragment went to %s, Go predicts %s (ports ignored for a fragment)", first, want)
	}
}

// TestGroupDatapath_IPv4SourceHash checks the IPv4 key layout matches.
func TestGroupDatapath_IPv4SourceHash(t *testing.T) {
	dp := loadDatapath(t)
	a, b := shardSID(0x10), shardSID(0x11)
	reachable(t, a, b)
	dp.apply(t, GroupPolicy{}, candidates(nil, a, b))
	for i := range 100 {
		src := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}) //nolint:gosec // test index
		_, got, argument := dp.send(t, udp4(src, netip.MustParseAddr("192.0.2.1"), 1, 53, 0))
		if want := predict(t, ShardPinKey{TableID: dpTableID, Src: src}, HashSource, a, b); got != want {
			t.Fatalf("IPv4 tenant %s went to %s, Go predicts %s", src, got, want)
		}
		if argument != dpArgument {
			t.Fatalf("IPv4 tenant %s: Argument %#x, want %#x", src, argument, dpArgument)
		}
	}
}
