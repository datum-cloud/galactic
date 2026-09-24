// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

import (
	"net/netip"
	"testing"
)

// loIfindex is the ingress interface a BPF_PROG_TEST_RUN reports when no
// context is supplied: the loopback device of the caller's network namespace.
const loIfindex uint32 = 1

var (
	srcTestShardSID = netip.MustParseAddr("fc00:1:2::1")
	srcTestShardPub = netip.MustParseAddr("2001:db8:9999::1")
	// srcTestTenantSID is a well-formed tenant SID: Block fc00:3:4, Node-ID 5,
	// Function End.DT46, Argument 0x123.
	srcTestTenantSID = netip.MustParseAddr("fc00:3:4:5:e123::")
	srcTestBackend   = netip.MustParseAddr("fd20:60::5")
	srcTestDest      = netip.MustParseAddr("2001:db8:9998::1")
)

// srcTestTenantBlock is the /48 covering srcTestTenantSID.
const srcTestTenantBlock = "fc00:3:4::/48"

// loadSrcFilterObjects loads the datapath with a NAT66 shard configured and
// the source filter in mode. populated arms the allow-list checks.
func loadSrcFilterObjects(t *testing.T, mode uint32, populated bool) *NatObjects {
	t.Helper()
	objs := loadObjects(t)
	if err := objs.ShardConfigTable.Put(uint32(0), NatShardConfig{
		ShardSid: srcTestShardSID.As16(), ShardPubAddr6: srcTestShardPub.As16(), ServesV6: 1,
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}
	cfg := NatSrcFilterConfig{Mode: mode}
	if populated {
		cfg.Populated = 1
	}
	if err := objs.NatSrcFilterConfig.Put(uint32(0), cfg); err != nil {
		t.Fatalf("populate nat_src_filter_config: %v", err)
	}
	return objs
}

func putAllow(t *testing.T, objs *NatObjects, prefix string, mask, flags uint32) {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	key := NatSrcAllowKey{Prefixlen: uint32(p.Bits()), Addr: p.Addr().As16()}
	if err := objs.NatSrcAllow.Put(key, NatSrcAllowValue{IfaceMask: mask, Flags: flags}); err != nil {
		t.Fatalf("populate nat_src_allow %s: %v", prefix, err)
	}
}

func putUplinkSlot(t *testing.T, objs *NatObjects, ifindex uint32, slot uint32) {
	t.Helper()
	if err := objs.NatUplinkSlot.Put(ifindex, slot); err != nil {
		t.Fatalf("populate nat_uplink_slot: %v", err)
	}
}

// encappedFromSource builds a tenant egress packet toward the shard SID with
// outer source src.
func encappedFromSource(t *testing.T, src netip.Addr) []byte {
	t.Helper()
	dst := srcTestShardSID.As16()
	dst[8] = (dst[8] & 0xF0) | 0x01
	dst[9] = 0x23
	return buildEncappedUDPPacket(t, netip.AddrFrom16(dst), src, srcTestBackend, srcTestDest, []byte("egress"))
}

func connCount(t *testing.T, objs *NatObjects) int {
	t.Helper()
	var (
		key   NatConnKey
		value NatConnValue
		n     int
	)
	it := objs.NatConnTable.Iterate()
	for it.Next(&key, &value) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate nat_conn_table: %v", err)
	}
	return n
}

func srcStat(t *testing.T, objs *NatObjects, index uint32) uint64 {
	t.Helper()
	return sumPerCPU(t, objs.NatSrcFilterStats, index)
}

func deniedCount(t *testing.T, objs *NatObjects) int {
	t.Helper()
	var (
		key   NatSrcDeniedKey
		value NatSrcDeniedValue
		n     int
	)
	it := objs.NatSrcDenied.Iterate()
	for it.Next(&key, &value) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate nat_src_denied: %v", err)
	}
	return n
}

// assertForwarded checks that a packet reached a forward leg: the leg claims a
// session row before it resolves a next hop, so a row exists whatever the
// host's routes make of the verdict.
func assertForwarded(t *testing.T, objs *NatObjects, ret uint32) {
	t.Helper()
	assertLeftFromDatapath(t, ret)
	if n := connCount(t, objs); n == 0 {
		t.Fatalf("no session row after the packet: it never reached a forward leg")
	}
}

// assertDenied checks that a packet was dropped by the source filter before
// any forward leg ran.
func assertDenied(t *testing.T, objs *NatObjects, ret uint32) {
	t.Helper()
	if ret != xdpDrop {
		t.Fatalf("verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if n := connCount(t, objs); n != 0 {
		t.Fatalf("%d session rows after a denied packet, want 0", n)
	}
}

func TestSrcFilter_OffIsNoOp(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	if err := objs.ShardConfigTable.Put(uint32(0), NatShardConfig{
		ShardSid: srcTestShardSID.As16(), ShardPubAddr6: srcTestShardPub.As16(), ServesV6: 1,
	}); err != nil {
		t.Fatalf("populate shard_config_table: %v", err)
	}

	ret, _, err := objs.NatIngress.Test(encappedFromSource(t, netip.MustParseAddr("fc00:3:4::a1b2")))
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	assertForwarded(t, objs, ret)
	if got := srcStat(t, objs, SrcStatChecked); got != 0 {
		t.Errorf("checked = %d with the filter off, want 0", got)
	}
}

func TestSrcFilter_AuditCountsAndForwards(t *testing.T) {
	tests := []struct {
		name      string
		populated bool
		src       netip.Addr
		wantStat  uint32
		wantDeny  bool
	}{
		{"StructureUnpopulated", false, netip.MustParseAddr("fc00:3:4::a1b2"), SrcStatDenyStructure, true},
		{"UnknownPrefix", true, srcTestTenantSID, SrcStatDenyPrefix, true},
		{"BypassUnpopulated", false, srcTestTenantSID, SrcStatBypassUnpopulated, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRoot(t)
			objs := loadSrcFilterObjects(t, SrcFilterModeAudit, tt.populated)

			ret, _, err := objs.NatIngress.Test(encappedFromSource(t, tt.src))
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			assertForwarded(t, objs, ret)
			if got := srcStat(t, objs, SrcStatChecked); got != 1 {
				t.Errorf("checked = %d, want 1", got)
			}
			if got := srcStat(t, objs, tt.wantStat); got != 1 {
				t.Errorf("%s = %d, want 1", SrcStatNames[tt.wantStat], got)
			}
			wantDenied := 0
			if tt.wantDeny {
				wantDenied = 1
			}
			if got := deniedCount(t, objs); got != wantDenied {
				t.Errorf("denied-source entries = %d, want %d", got, wantDenied)
			}
		})
	}
}

func TestSrcFilter_EnforceDeniesStructure(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"FunctionNotEndDT46", "fc00:3:4:5:f123::"},
		{"FunctionZero", "fc00:3:4:5:123::"},
		{"ArgumentZero", "fc00:3:4:5:e000::"},
		{"PaddingSet", "fc00:3:4:5:e123::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRoot(t)
			objs := loadSrcFilterObjects(t, SrcFilterModeEnforce, false)

			ret, _, err := objs.NatIngress.Test(encappedFromSource(t, netip.MustParseAddr(tt.src)))
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			assertDenied(t, objs, ret)
			if got := srcStat(t, objs, SrcStatDenyStructure); got != 1 {
				t.Errorf("deny_structure = %d, want 1", got)
			}
		})
	}
}

func TestSrcFilter_EnforceAllowList(t *testing.T) {
	tests := []struct {
		name        string
		allowPrefix string
		allowMask   uint32
		allowFlags  uint32
		slotLo      *uint32
		wantAllowed bool
		wantStat    uint32
	}{
		{"UnknownPrefix", "fc00:9::/48", 1, 0, ptr(0), false, SrcStatDenyPrefix},
		{"MatchingSlot", srcTestTenantBlock, 1 << 2, 0, ptr(2), true, SrcStatAllowed},
		{"LongerPrefix", "fc00:3:4:5::/64", 1, 0, ptr(0), true, SrcStatAllowed},
		{"WrongSlot", srcTestTenantBlock, 1 << 0, 0, ptr(3), false, SrcStatDenyInterface},
		{"UnslottedInterface", srcTestTenantBlock, 1, 0, nil, false, SrcStatDenyInterface},
		{"AnyInterface", srcTestTenantBlock, 0, SrcAllowFlagAnyInterface, nil, true, SrcStatAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRoot(t)
			objs := loadSrcFilterObjects(t, SrcFilterModeEnforce, true)
			putAllow(t, objs, tt.allowPrefix, tt.allowMask, tt.allowFlags)
			if tt.slotLo != nil {
				putUplinkSlot(t, objs, loIfindex, *tt.slotLo)
			}

			ret, _, err := objs.NatIngress.Test(encappedFromSource(t, srcTestTenantSID))
			if err != nil {
				t.Fatalf("program test-run: %v", err)
			}
			if tt.wantAllowed {
				assertForwarded(t, objs, ret)
				if got := deniedCount(t, objs); got != 0 {
					t.Errorf("denied-source entries = %d, want 0", got)
				}
			} else {
				assertDenied(t, objs, ret)
				assertDeniedRecord(t, objs, tt.wantStat)
			}
			if got := srcStat(t, objs, tt.wantStat); got != 1 {
				t.Errorf("%s = %d, want 1", SrcStatNames[tt.wantStat], got)
			}
		})
	}
}

func TestSrcFilter_EnforceUnpopulatedBypassesAllowList(t *testing.T) {
	requireRoot(t)
	objs := loadSrcFilterObjects(t, SrcFilterModeEnforce, false)

	ret, _, err := objs.NatIngress.Test(encappedFromSource(t, srcTestTenantSID))
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	assertForwarded(t, objs, ret)
	if got := srcStat(t, objs, SrcStatBypassUnpopulated); got != 1 {
		t.Errorf("bypass_unpopulated = %d, want 1", got)
	}
	if got := srcStat(t, objs, SrcStatAllowed); got != 0 {
		t.Errorf("allowed = %d, want 0: a bypass is not an allow", got)
	}
}

func TestSrcFilter_NonShardTrafficUntouched(t *testing.T) {
	requireRoot(t)
	objs := loadSrcFilterObjects(t, SrcFilterModeEnforce, true)

	unclaimed := buildUDPPacket(t, netip.MustParseAddr("2001:db8::9999"),
		netip.MustParseAddr("2001:db8:ffff::1"), 5000, 443, []byte("hi"))
	ret, out, err := objs.NatIngress.Test(unclaimed)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("unclaimed verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
	if string(out) != string(unclaimed) {
		t.Errorf("unclaimed packet mutated")
	}

	otherNode := buildEncappedUDPPacket(t, netip.MustParseAddr("fc00:1:3:0:e123::"),
		netip.MustParseAddr("fc00:9::1"), srcTestBackend, srcTestDest, []byte("x"))
	ret, _, err = objs.NatIngress.Test(otherNode)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("other-locator verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
	}

	reply := buildUDPPacket(t, srcTestShardPub, srcTestDest, 443, 40000, []byte("r"))
	if _, _, err := objs.NatIngress.Test(reply); err != nil {
		t.Fatalf("program test-run: %v", err)
	}

	if got := srcStat(t, objs, SrcStatChecked); got != 0 {
		t.Errorf("checked = %d, want 0: only traffic to the shard SID is filtered", got)
	}
}

func assertDeniedRecord(t *testing.T, objs *NatObjects, wantReason uint32) {
	t.Helper()
	var key NatSrcDeniedKey
	copy(key.Locator[:], srcTestTenantSID.AsSlice()[:8])
	var value NatSrcDeniedValue
	if err := objs.NatSrcDenied.Lookup(key, &value); err != nil {
		t.Fatalf("lookup nat_src_denied for the source locator: %v", err)
	}
	if value.Packets != 1 || value.LastReason != wantReason || value.LastIfindex != loIfindex {
		t.Errorf("denied record = %+v, want 1 packet, reason %d, ifindex %d",
			value, wantReason, loIfindex)
	}
	if value.LastSeenNs == 0 {
		t.Errorf("denied record has no timestamp")
	}
}

func ptr(v uint32) *uint32 { return &v }
