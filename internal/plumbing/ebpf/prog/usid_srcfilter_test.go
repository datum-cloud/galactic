// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"bytes"
	"errors"
	"net/netip"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// testRunIfindex is the skb->ifindex BPF_PROG_TEST_RUN uses when no context is
// supplied: the loopback device.
const testRunIfindex uint32 = 1

var (
	fabricPeerSrc = netip.MustParseAddr("fd00:aa:1:2::1")
	fabricPrefix  = netip.MustParsePrefix("fd00:aa::/32")
	outsideSrc    = netip.MustParseAddr("2001:db8:ffff:1::1")
)

// srcFilterFixture is a loaded datapath with one claimed uSID whose vrf_table
// entry points at a routing table that does not exist, so a packet the source
// filter lets through ends at DROP_REASON_FIB_LOOKUP_FAILED. Reaching that
// reason proves the filter passed the packet on to the rest of the path.
type srcFilterFixture struct {
	objs *UsidObjects
	usid testUSID
}

func newSrcFilterFixture(t *testing.T) *srcFilterFixture {
	t.Helper()
	requireRoot(t)
	f := &srcFilterFixture{
		objs: loadObjects(t),
		usid: testUSID{block: baseUSID.block, nodeID: baseUSID.nodeID, function: uformat.FunctionEndDT46, argument: 0x321},
	}
	if err := f.objs.LocatorTable.Put(f.usid.locatorKey(t), UsidLocatorValue{Generation: 1}); err != nil {
		t.Fatalf("populate locator_table: %v", err)
	}
	if err := f.objs.FunctionTable.Put(f.usid.functionKey(t), UsidFunctionValue{Behavior: 1}); err != nil {
		t.Fatalf("populate function_table: %v", err)
	}
	if err := f.objs.VrfTable.Put(f.usid.vrfKey(), UsidVrfValue{VrfTableId: 0x3A3A3A}); err != nil {
		t.Fatalf("populate vrf_table: %v", err)
	}
	return f
}

func (f *srcFilterFixture) setConfig(t *testing.T, mode uint32, populated bool) {
	t.Helper()
	cfg := UsidSrcFilterConfig{Mode: mode, Generation: 1}
	if populated {
		cfg.Populated = 1
	}
	if err := f.objs.SrcFilterConfigTable.Put(uint32(0), cfg); err != nil {
		t.Fatalf("write src_filter_config_table: %v", err)
	}
}

func (f *srcFilterFixture) allow(t *testing.T, prefix netip.Prefix, ifaceMask, flags uint32) {
	t.Helper()
	key := UsidSrcAllowKey{Prefixlen: uint32(prefix.Bits()), Addr: prefix.Masked().Addr().As16()}
	if err := f.objs.SrcAllowTable.Put(key, UsidSrcAllowValue{IfaceMask: ifaceMask, Flags: flags}); err != nil {
		t.Fatalf("populate src_allow_table[%s]: %v", prefix, err)
	}
}

func (f *srcFilterFixture) setSlot(t *testing.T, ifindex, slot uint32) {
	t.Helper()
	if err := f.objs.UplinkSlotTable.Put(ifindex, slot); err != nil {
		t.Fatalf("populate uplink_slot_table[%d]: %v", ifindex, err)
	}
}

func (f *srcFilterFixture) packet(t *testing.T, src netip.Addr) []byte {
	t.Helper()
	return buildPacket(t, f.usid.addr(t), src, true)
}

func (f *srcFilterFixture) run(t *testing.T, pkt []byte) uint32 {
	t.Helper()
	ret, _, err := f.objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	return ret
}

// wantStats asserts every src_filter_stats slot, with any slot absent from want
// expected to be zero.
func (f *srcFilterFixture) wantStats(t *testing.T, want map[uint32]uint64) {
	t.Helper()
	for i := range SrcFilterStatSlots {
		if got := sumPerCPU(t, f.objs.SrcFilterStats, i); got != want[i] {
			t.Errorf("src_filter_stats[%s] = %d, want %d", srcFilterStatName(i), got, want[i])
		}
	}
}

// wantForwarded asserts the packet passed the filter and reached the FIB lookup.
func (f *srcFilterFixture) wantForwarded(t *testing.T, ret uint32) {
	t.Helper()
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT from the FIB lookup (%d)", ret, tcActShot)
	}
	assertOnlyDropReason(t, f.objs.DropReasons, DropReasonFibLookupFailed, 1)
	if got := f.vrfPackets(t); got != 1 {
		t.Errorf("vrf_table packets = %d, want 1", got)
	}
}

// wantFiltered asserts the filter dropped the packet before any uSID decode
// step past the locator match.
func (f *srcFilterFixture) wantFiltered(t *testing.T, ret uint32) {
	t.Helper()
	if ret != tcActShot {
		t.Errorf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	assertOnlyDropReason(t, f.objs.DropReasons, 0, 0)
	if got := f.vrfPackets(t); got != 0 {
		t.Errorf("vrf_table packets = %d, want 0: a filtered packet must not reach vrf_table", got)
	}
}

func (f *srcFilterFixture) vrfPackets(t *testing.T) uint64 {
	t.Helper()
	var v UsidVrfValue
	if err := f.objs.VrfTable.Lookup(f.usid.vrfKey(), &v); err != nil {
		t.Fatalf("lookup vrf_table: %v", err)
	}
	return v.Packets
}

// wantDenied asserts src_filter_denied holds src's /64 with the given count and
// reason.
func (f *srcFilterFixture) wantDenied(t *testing.T, src netip.Addr, count uint64, reason, ifindex uint32) {
	t.Helper()
	var key UsidSrcDeniedKey
	a := src.As16()
	copy(key.Prefix[:], a[:8])
	var v UsidSrcDeniedValue
	if err := f.objs.SrcFilterDenied.Lookup(key, &v); err != nil {
		t.Fatalf("lookup src_filter_denied[%s/64]: %v", src, err)
	}
	if v.Count != count || v.LastReason != reason || v.LastIfindex != ifindex || v.LastNs == 0 {
		t.Errorf("src_filter_denied[%s/64] = %+v, want count %d reason %s ifindex %d and a timestamp",
			src, v, count, srcFilterStatName(reason), ifindex)
	}
}

func (f *srcFilterFixture) wantNoDenials(t *testing.T) {
	t.Helper()
	var key UsidSrcDeniedKey
	var v UsidSrcDeniedValue
	if f.objs.SrcFilterDenied.Iterate().Next(&key, &v) {
		t.Errorf("src_filter_denied has entry %x = %+v, want none", key.Prefix, v)
	}
}

func srcFilterStatName(i uint32) string {
	if name, ok := SrcFilterStatNames[i]; ok {
		return name
	}
	return "reserved"
}

func TestUsidIngressSrcFilter_ModeOffIsNoOp(t *testing.T) {
	f := newSrcFilterFixture(t)
	f.setConfig(t, SrcFilterModeOff, true)

	f.wantForwarded(t, f.run(t, f.packet(t, outsideSrc)))
	f.wantStats(t, nil)
	f.wantNoDenials(t)
}

func TestUsidIngressSrcFilter_DefaultConfigIsOff(t *testing.T) {
	f := newSrcFilterFixture(t)

	f.wantForwarded(t, f.run(t, f.packet(t, outsideSrc)))
	f.wantStats(t, nil)
}

func TestUsidIngressSrcFilter_AuditCountsAndForwards(t *testing.T) {
	f := newSrcFilterFixture(t)
	f.setConfig(t, SrcFilterModeAudit, true)
	f.allow(t, fabricPrefix, 0, SrcFilterFlagAnyIface)

	f.wantForwarded(t, f.run(t, f.packet(t, outsideSrc)))
	f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 1, SrcFilterStatDenyPrefix: 1})
	f.wantDenied(t, outsideSrc, 1, SrcFilterStatDenyPrefix, testRunIfindex)
}

func TestUsidIngressSrcFilter_AuditAllowedSource(t *testing.T) {
	f := newSrcFilterFixture(t)
	f.setConfig(t, SrcFilterModeAudit, true)
	f.allow(t, fabricPrefix, 0, SrcFilterFlagAnyIface)

	f.wantForwarded(t, f.run(t, f.packet(t, fabricPeerSrc)))
	f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 1, SrcFilterStatAllowed: 1})
	f.wantNoDenials(t)
}

func TestUsidIngressSrcFilter_EnforcePrefixMissDrops(t *testing.T) {
	f := newSrcFilterFixture(t)
	f.setConfig(t, SrcFilterModeEnforce, true)
	f.allow(t, fabricPrefix, 0, SrcFilterFlagAnyIface)

	pkt := f.packet(t, outsideSrc)
	f.wantFiltered(t, f.run(t, pkt))
	f.wantFiltered(t, f.run(t, pkt))
	f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 2, SrcFilterStatDenyPrefix: 2})
	f.wantDenied(t, outsideSrc, 2, SrcFilterStatDenyPrefix, testRunIfindex)
}

func TestUsidIngressSrcFilter_EnforceEmptyAllowListDrops(t *testing.T) {
	f := newSrcFilterFixture(t)
	f.setConfig(t, SrcFilterModeEnforce, true)

	f.wantFiltered(t, f.run(t, f.packet(t, fabricPeerSrc)))
	f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 1, SrcFilterStatDenyPrefix: 1})
}

func TestUsidIngressSrcFilter_EnforceInterfaceBinding(t *testing.T) {
	tests := []struct {
		name      string
		slot      *uint32
		ifaceMask uint32
		flags     uint32
		wantAllow bool
	}{
		{"BoundSlotAllowed", ptr(uint32(3)), 1 << 3, 0, true},
		{"OneOfSeveralSlotsAllowed", ptr(uint32(3)), 1<<0 | 1<<3 | 1<<31, 0, true},
		{"WrongSlotDropped", ptr(uint32(3)), 1 << 4, 0, false},
		{"EmptyMaskDropped", ptr(uint32(0)), 0, 0, false},
		{"UnknownUplinkDropped", nil, ^uint32(0), 0, false},
		{"SlotOutOfRangeDropped", ptr(uint32(40)), ^uint32(0), 0, false},
		{"AnyIfaceAllowedOnUnknownUplink", nil, 0, SrcFilterFlagAnyIface, true},
		{"AnyIfaceAllowedOnWrongSlot", ptr(uint32(3)), 1 << 4, SrcFilterFlagAnyIface, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSrcFilterFixture(t)
			f.setConfig(t, SrcFilterModeEnforce, true)
			f.allow(t, fabricPrefix, tt.ifaceMask, tt.flags)
			if tt.slot != nil {
				f.setSlot(t, testRunIfindex, *tt.slot)
			}

			ret := f.run(t, f.packet(t, fabricPeerSrc))
			if tt.wantAllow {
				f.wantForwarded(t, ret)
				f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 1, SrcFilterStatAllowed: 1})
				return
			}
			f.wantFiltered(t, ret)
			f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 1, SrcFilterStatDenyIface: 1})
			f.wantDenied(t, fabricPeerSrc, 1, SrcFilterStatDenyIface, testRunIfindex)
		})
	}
}

func TestUsidIngressSrcFilter_LongestPrefixWins(t *testing.T) {
	f := newSrcFilterFixture(t)
	f.setConfig(t, SrcFilterModeEnforce, true)
	f.setSlot(t, testRunIfindex, 1)
	f.allow(t, fabricPrefix, 1<<1, 0)
	f.allow(t, netip.PrefixFrom(fabricPeerSrc, 64).Masked(), 1<<2, 0)

	f.wantFiltered(t, f.run(t, f.packet(t, fabricPeerSrc)))
	f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 1, SrcFilterStatDenyIface: 1})
}

func TestUsidIngressSrcFilter_UnpopulatedFailsOpen(t *testing.T) {
	for _, mode := range []uint32{SrcFilterModeAudit, SrcFilterModeEnforce} {
		f := newSrcFilterFixture(t)
		f.setConfig(t, mode, false)

		f.wantForwarded(t, f.run(t, f.packet(t, outsideSrc)))
		f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 1, SrcFilterStatBypassUnpopulated: 1})
		f.wantNoDenials(t)
	}
}

func TestUsidIngressSrcFilter_LocatorMissNeverChecked(t *testing.T) {
	f := newSrcFilterFixture(t)
	f.setConfig(t, SrcFilterModeEnforce, true)

	other := testUSID{block: 0xFFEEDDCCBBAA, nodeID: 0x0002, function: uformat.FunctionEndDT46, argument: 0x001}
	pkt := buildPacket(t, other.addr(t), outsideSrc, true)

	ret, out, err := f.objs.UsidIngress.Test(pkt)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	if ret != tcActUnspec {
		t.Errorf("verdict = %d, want TC_ACT_UNSPEC (%d)", ret, tcActUnspec)
	}
	if !bytes.Equal(out, pkt) {
		t.Errorf("packet mutated on a locator_table miss:\n in: % x\nout: % x", pkt, out)
	}
	f.wantStats(t, nil)
	f.wantNoDenials(t)
}

// skbContext is the leading part of struct __sk_buff that BPF_PROG_TEST_RUN
// accepts as input, up to and including ifindex. Every other field must be
// zero.
type skbContext struct {
	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VlanPresent    uint32
	VlanTci        uint32
	VlanProto      uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
}

// TestUsidIngressSrcFilter_BindsToArrivalInterface runs the program with its
// skb on a real device in a private network namespace, proving the binding
// check keys on the interface the packet arrived on rather than a fixed value.
func TestUsidIngressSrcFilter_BindsToArrivalInterface(t *testing.T) {
	f := newSrcFilterFixture(t)

	runtime.LockOSThread()
	origNS := openThreadNetns(t)
	t.Cleanup(func() {
		if err := unix.Setns(origNS, unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore original network namespace: %v", err)
			return
		}
		_ = unix.Close(origNS)
		runtime.UnlockOSThread()
	})
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare network namespace: %v", err)
	}
	for _, name := range []string{"sf0", "sf1"} {
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			t.Fatalf("add dummy link %s: %v", name, err)
		}
	}
	bound := uint32(setLinkUp(t, "sf0").Attrs().Index)
	other := uint32(setLinkUp(t, "sf1").Attrs().Index)

	f.setConfig(t, SrcFilterModeEnforce, true)
	f.setSlot(t, bound, 5)
	f.setSlot(t, other, 6)
	f.allow(t, fabricPrefix, 1<<5, 0)

	runOn := func(ifindex uint32) uint32 {
		t.Helper()
		pkt := f.packet(t, fabricPeerSrc)
		ret, err := f.objs.UsidIngress.Run(&ebpf.RunOptions{
			Data:    pkt,
			DataOut: make([]byte, len(pkt)+256),
			Context: skbContext{Ifindex: ifindex},
			Repeat:  1,
		})
		if err != nil {
			if errors.Is(err, ebpf.ErrNotSupported) {
				t.Skipf("kernel cannot run tc programs with a context: %v", err)
			}
			t.Fatalf("program test-run on ifindex %d: %v", ifindex, err)
		}
		return ret
	}

	f.wantFiltered(t, runOn(other))
	f.wantStats(t, map[uint32]uint64{SrcFilterStatChecked: 1, SrcFilterStatDenyIface: 1})
	f.wantDenied(t, fabricPeerSrc, 1, SrcFilterStatDenyIface, other)

	f.wantForwarded(t, runOn(bound))
	f.wantStats(t, map[uint32]uint64{
		SrcFilterStatChecked: 2, SrcFilterStatDenyIface: 1, SrcFilterStatAllowed: 1,
	})
}

func ptr[T any](v T) *T { return &v }
