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

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// fakeGroupStore is an in-memory GroupStore. Publish is atomic, as the kernel
// store's swap is: a failed publication changes nothing. fail, when set,
// decides whether a publication fails.
type fakeGroupStore struct {
	published map[uint32]prog.UsidEgressShardGroupValue
	attempts  []prog.UsidEgressShardGroupValue
	fail      func(groupID uint32, value prog.UsidEgressShardGroupValue) error
}

func newFakeGroupStore() *fakeGroupStore {
	return &fakeGroupStore{published: map[uint32]prog.UsidEgressShardGroupValue{}}
}

func (f *fakeGroupStore) Load(groupID uint32) (prog.UsidEgressShardGroupValue, bool, error) {
	v, ok := f.published[groupID]
	return v, ok, nil
}

func (f *fakeGroupStore) Publish(groupID uint32, value prog.UsidEgressShardGroupValue) error {
	f.attempts = append(f.attempts, value)
	if f.fail != nil {
		if err := f.fail(groupID, value); err != nil {
			return err
		}
	}
	f.published[groupID] = value
	return nil
}

var errInjected = errors.New("injected publication failure")

func applyOK(t *testing.T, g *ShardGroupTable, policy GroupPolicy, c []ShardCandidate) GroupResult {
	t.Helper()
	result, err := g.Apply(NAT66ShardGroup, policy, c)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return result
}

func published(t *testing.T, store *fakeGroupStore) prog.UsidEgressShardGroupValue {
	t.Helper()
	v, ok := store.published[NAT66ShardGroup]
	if !ok {
		t.Fatal("no snapshot published")
	}
	return v
}

func slotOf(t *testing.T, r GroupResult, sid netip.Addr) ShardState {
	t.Helper()
	for _, s := range r.Shards {
		if s.SID == sid {
			return s
		}
	}
	t.Fatalf("shard %s not in result %+v", sid, r.Shards)
	return ShardState{}
}

// TestApplyPublishesOneSnapshot checks that Apply strips the Argument,
// resolves next hops, fills every Maglev slot with an active shard's index,
// records the class, and publishes it all as one value.
func TestApplyPublishesOneSnapshot(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	a, b := shardSID(0x10), shardSID(0x11)
	reachable(t, a, b)

	withArgument := a.As16()
	withArgument[9] = 0x42
	result := applyOK(t, g, GroupPolicy{PinIdle: time.Minute, Ineligible: 1}, []ShardCandidate{
		{SID: net.IP(withArgument[:])}, {SID: net.IP(b.AsSlice())},
	})
	if !result.Changed || result.Generation != 1 || result.Active() != 2 || len(store.attempts) != 1 {
		t.Fatalf("result = %+v after %d publications, want one publication, generation 1, 2 active",
			result, len(store.attempts))
	}
	v := published(t, store)
	if v.Flags&groupFlagEnabled == 0 || v.Candidates != 2 || v.Active != 2 || v.PinIdleSec != 60 ||
		v.Ineligible != 1 || v.ClassKind != classKindNAT66 {
		t.Errorf("snapshot header = %+v, want enabled NAT66, 2 candidates, 2 active, 1 ineligible, pin 60s", v)
	}
	counts := map[uint8]int{}
	for _, slot := range v.Maglev {
		counts[slot]++
	}
	if len(counts) != 2 || counts[shardSlotNone] != 0 {
		t.Errorf("Maglev slots use %v, want exactly the two shard slots", counts)
	}
	stored := v.Shards[slotOf(t, result, a).Slot]
	if netip.AddrFrom16(stored.Sid) != a || stored.Flags != shardFlagAlive || stored.LinkIfindex != 1 ||
		net.HardwareAddr(stored.Dmac[:]).String() != dpShardMAC.String() || stored.Generation == 0 {
		t.Errorf("member = %+v, want base SID %s, alive, resolved next hop, nonzero generation", stored, a)
	}

	again := applyOK(t, g, GroupPolicy{PinIdle: time.Minute, Ineligible: 1},
		candidates(nil, b, a))
	if again.Changed || len(store.attempts) != 1 {
		t.Errorf("unchanged rebuild published again (changed %v, %d publications)", again.Changed, len(store.attempts))
	}
}

// TestApplyKeepsSlotsAndGenerations checks that a shard keeps its slot and
// generation across rebuilds and a new shard takes a fresh generation, and
// that a freed slot reused by another shard never reuses a generation.
func TestApplyKeepsSlotsAndGenerations(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	a, b, c, d := shardSID(0x10), shardSID(0x11), shardSID(0x12), shardSID(0x13)
	reachable(t, a, b, c, d)

	first := applyOK(t, g, GroupPolicy{}, candidates(nil, a, b))
	third := applyOK(t, g, GroupPolicy{}, candidates(nil, a, b, c))
	if slotOf(t, third, a) != withAssigned(slotOf(t, first, a), false) ||
		slotOf(t, third, b).Generation != slotOf(t, first, b).Generation {
		t.Errorf("existing shards changed slot or generation: before %+v, after %+v", first.Shards, third.Shards)
	}
	if !slotOf(t, third, c).Assigned || slotOf(t, third, a).Assigned {
		t.Errorf("Assigned wrong: a %v c %v", slotOf(t, third, a).Assigned, slotOf(t, third, c).Assigned)
	}

	applyOK(t, g, GroupPolicy{}, candidates(nil, b, c))
	if published(t, store).Shards[slotOf(t, first, a).Slot].Sid != [16]byte{} {
		t.Error("slot still holds a after it left")
	}
	fifth := applyOK(t, g, GroupPolicy{}, candidates(nil, b, c, d))
	if slotOf(t, fifth, d).Slot != slotOf(t, first, a).Slot {
		t.Errorf("d took slot %d, want the freed slot %d", slotOf(t, fifth, d).Slot, slotOf(t, first, a).Slot)
	}
	seen := map[uint32]netip.Addr{}
	for _, r := range []GroupResult{first, third, fifth} {
		for _, s := range r.Shards {
			if other, dup := seen[s.Generation]; dup && other != s.SID {
				t.Errorf("generation %d given to both %s and %s", s.Generation, other, s.SID)
			}
			seen[s.Generation] = s.SID
		}
	}
}

func withAssigned(s ShardState, assigned bool) ShardState {
	s.Assigned = assigned
	return s
}

// TestApplyGenerationsSurvivePartialPublication reproduces the review's F05
// sequence. A occupies slot 0. B replaces A, but publishing B fails, so the
// published snapshot still holds A. C replaces B before any successful
// publication. C's generation must differ from both A's and the generation B
// was allocated, so no pin made for either can follow C.
func TestApplyGenerationsSurvivePartialPublication(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	a, b, c := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachable(t, a, b, c)

	ra := applyOK(t, g, GroupPolicy{}, candidates(nil, a))
	genA := slotOf(t, ra, a).Generation

	store.fail = func(uint32, prog.UsidEgressShardGroupValue) error { return errInjected }
	rb, err := g.Apply(NAT66ShardGroup, GroupPolicy{}, candidates(nil, b))
	if !errors.Is(err, errInjected) {
		t.Fatalf("Apply(B) error = %v, want the injected failure", err)
	}
	genB := slotOf(t, rb, b).Generation
	if v := published(t, store); netip.AddrFrom16(v.Shards[0].Sid) != a || v.Shards[0].Generation != genA {
		t.Fatalf("published slot 0 = %s gen %d after the failed publication, want A gen %d",
			netip.AddrFrom16(v.Shards[0].Sid), v.Shards[0].Generation, genA)
	}

	store.fail = nil
	rc := applyOK(t, g, GroupPolicy{}, candidates(nil, c))
	genC := slotOf(t, rc, c).Generation
	if genC == genA || genC == genB || genB == genA {
		t.Errorf("generations A=%d B=%d C=%d, want all distinct", genA, genB, genC)
	}
	if v := published(t, store); v.NextSlotGeneration <= genC {
		t.Errorf("published next_slot_generation %d, want above every handed-out generation (C=%d)",
			v.NextSlotGeneration, genC)
	}
}

// TestApplyGenerationsAcrossFailuresRetriesAndRestart drives a long sequence
// of replacements with failures injected at random publications, a retry
// after each, a disable and re-enable, and a restart from the published
// snapshot, and checks no generation is ever handed to two shards.
func TestApplyGenerationsAcrossFailuresRetriesAndRestart(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	sids := make([]netip.Addr, 0, 40)
	for i := range 40 {
		sids = append(sids, shardSID(uint16(0x100+i))) //nolint:gosec // test index
	}
	reachable(t, sids...)

	owner := map[uint32]netip.Addr{}
	check := func(r GroupResult) {
		for _, s := range r.Shards {
			if prev, ok := owner[s.Generation]; ok && prev != s.SID {
				t.Fatalf("generation %d handed to %s after %s", s.Generation, s.SID, prev)
			}
			owner[s.Generation] = s.SID
		}
	}
	for i := range 39 {
		n := 0
		store.fail = func(uint32, prog.UsidEgressShardGroupValue) error {
			n++
			if i%3 == 0 && n == 1 {
				return errInjected
			}
			return nil
		}
		set := candidates(nil, sids[i], sids[i+1])
		r, err := g.Apply(NAT66ShardGroup, GroupPolicy{}, set)
		check(r)
		if err != nil {
			r, err = g.Apply(NAT66ShardGroup, GroupPolicy{}, set) // retry
			if err != nil {
				t.Fatalf("retry %d: %v", i, err)
			}
			check(r)
		}
		if i == 20 {
			if _, err := g.Disable(NAT66ShardGroup); err != nil {
				t.Fatal(err)
			}
		}
		if i == 30 {
			g = NewShardGroupTable(store) // a restarted galactic-cni
		}
	}
}

// TestApplyClassChangeStartsAfresh checks a group that changes class keeps no
// slot, so no pin made for the old class is honoured.
func TestApplyClassChangeStartsAfresh(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	a := shardSID(0x10)
	reachable(t, a)
	first := applyOK(t, g, GroupPolicy{Class: NAT64Class(netip.MustParsePrefix("2001:db8:64::/96"))},
		candidates(nil, a))
	second := applyOK(t, g, GroupPolicy{Class: NAT64Class(WellKnownPrefix)}, candidates(nil, a))
	if !slotOf(t, second, a).Assigned || slotOf(t, second, a).Generation == slotOf(t, first, a).Generation {
		t.Errorf("class change kept the member's tenure: before %+v, after %+v", first.Shards, second.Shards)
	}
	status, _ := g.Status(NAT66ShardGroup)
	if status.Class != NAT64Class(WellKnownPrefix) {
		t.Errorf("published class %s, want nat64:64:ff9b::/96", status.Class)
	}
}

// TestApplyExcludesDrainingAndUnreachableFromTheTable checks that only alive,
// non-draining shards appear in the Maglev table, while both other kinds stay
// candidates.
func TestApplyExcludesDrainingAndUnreachableFromTheTable(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	a, b, c := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachable(t, a, b) // c does not resolve

	result := applyOK(t, g, GroupPolicy{}, candidates(map[netip.Addr]bool{b: true}, a, b, c))
	if result.Active() != 1 {
		t.Fatalf("active = %d, want 1", result.Active())
	}
	if s := slotOf(t, result, c); s.Alive || s.Err == nil {
		t.Errorf("unreachable shard state %+v, want not alive with an error", s)
	}
	v := published(t, store)
	if v.Candidates != 3 || v.Active != 1 {
		t.Errorf("snapshot candidates %d active %d, want 3 and 1", v.Candidates, v.Active)
	}
	onlyA := uint8(slotOf(t, result, a).Slot) //nolint:gosec // < 32
	for i, slot := range v.Maglev {
		if slot != onlyA {
			t.Fatalf("Maglev slot %d = %d, want every slot on %s (slot %d)", i, slot, a, onlyA)
		}
	}
	if f := v.Shards[slotOf(t, result, b).Slot].Flags; f != shardFlagAlive|shardFlagDraining {
		t.Errorf("draining shard flags %#x, want alive|draining", f)
	}
}

// TestApplyWithNoActiveShardEmptiesTheTable checks that a group whose shards
// are all unreachable stays enabled with every slot empty, which the datapath
// drops on.
func TestApplyWithNoActiveShardEmptiesTheTable(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	reachable(t)
	applyOK(t, g, GroupPolicy{}, candidates(nil, shardSID(0x10)))
	status, err := g.Status(NAT66ShardGroup)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Open() || status.Candidates != 1 || status.Active != 0 {
		t.Errorf("status = %+v, want open with 1 candidate and none active", status)
	}
	for i, slot := range published(t, store).Maglev {
		if slot != shardSlotNone {
			t.Fatalf("Maglev slot %d = %d, want none", i, slot)
		}
	}
}

// TestApplyRejectsTooManyShardsAndBadSIDs checks Apply's input validation.
func TestApplyRejectsTooManyShardsAndBadSIDs(t *testing.T) {
	g := NewShardGroupTable(newFakeGroupStore())
	reachable(t)
	many := make([]netip.Addr, 0, MaxShardsPerGroup+1)
	for i := range MaxShardsPerGroup + 1 {
		many = append(many, shardSID(uint16(0x100+i))) //nolint:gosec // test index
	}
	if _, err := g.Apply(NAT66ShardGroup, GroupPolicy{}, candidates(nil, many...)); err == nil {
		t.Error("Apply with 33 shards = nil, want an error")
	}
	padded := []ShardCandidate{{SID: net.ParseIP("2001:db8::1:2:3")}}
	if _, err := g.Apply(NAT66ShardGroup, GroupPolicy{}, padded); err == nil {
		t.Error("Apply with a SID whose padding is set = nil, want an error")
	}
	if _, err := g.Apply(MaxShardGroups, GroupPolicy{}, nil); err == nil {
		t.Error("Apply to an out-of-range group = nil, want an error")
	}
}

// TestCloseKeepsForwardingAndRefusesNewRoutes checks Close: the group stays
// enabled with its members and their generations, and reads as no longer open.
func TestCloseKeepsForwardingAndRefusesNewRoutes(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	a := shardSID(0x10)
	reachable(t, a)
	before := applyOK(t, g, GroupPolicy{PinIdle: time.Hour}, candidates(nil, a))

	closing, err := g.Close(NAT66ShardGroup)
	if err != nil || !closing {
		t.Fatalf("Close = %v, %v, want closing", closing, err)
	}
	status, _ := g.Status(NAT66ShardGroup)
	if !status.Enabled || !status.Closing || status.Open() || status.Active != 1 {
		t.Errorf("status after Close = %+v, want enabled, closing, not open, 1 active", status)
	}
	members, _ := g.Members(NAT66ShardGroup)
	if len(members) != 1 || members[0].Generation != slotOf(t, before, a).Generation {
		t.Errorf("members after Close = %+v, want a with its generation kept", members)
	}
	if v := published(t, store); v.PinIdleSec != 3600 {
		t.Errorf("pin idle after Close = %d, want the group's own 3600", v.PinIdleSec)
	}

	if closing, _ := NewShardGroupTable(newFakeGroupStore()).Close(NAT66ShardGroup); closing {
		t.Error("Close of a group never published reported closing")
	}
}

// TestDisableKeepsTheGenerationCounter checks Disable turns the group off,
// clears every slot, is a no-op the second time, and that a re-enabled group
// hands out generations above everything before it.
func TestDisableKeepsTheGenerationCounter(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	a := shardSID(0x10)
	reachable(t, a)
	before := applyOK(t, g, GroupPolicy{}, candidates(nil, a))

	changed, err := g.Disable(NAT66ShardGroup)
	if err != nil || !changed {
		t.Fatalf("Disable = %v, %v, want changed", changed, err)
	}
	status, _ := g.Status(NAT66ShardGroup)
	if status.Enabled || status.Candidates != 0 {
		t.Errorf("status after Disable = %+v, want disabled and empty", status)
	}
	if members, _ := g.Members(NAT66ShardGroup); len(members) != 0 {
		t.Errorf("members after Disable = %v, want none", members)
	}
	if changed, err := g.Disable(NAT66ShardGroup); err != nil || changed {
		t.Errorf("second Disable = %v, %v, want unchanged", changed, err)
	}
	after := applyOK(t, NewShardGroupTable(store), GroupPolicy{}, candidates(nil, a))
	if slotOf(t, after, a).Generation <= slotOf(t, before, a).Generation {
		t.Errorf("re-enabled generation %d, want above %d", slotOf(t, after, a).Generation,
			slotOf(t, before, a).Generation)
	}
}

// TestFindClassAndAnyOpen checks the lookups CNI ADD makes.
func TestFindClassAndAnyOpen(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	a := shardSID(0x10)
	reachable(t, a)
	nsp := NAT64Class(netip.MustParsePrefix("2001:db8:64::/96"))
	if _, err := g.Apply(NAT66ShardGroup, GroupPolicy{}, candidates(nil, a)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Apply(2, GroupPolicy{Class: nsp}, candidates(nil, a)); err != nil {
		t.Fatal(err)
	}
	if id, _, ok, _ := g.FindClass(nsp); !ok || id != 2 {
		t.Errorf("FindClass(%s) = %d, %v, want group 2", nsp, id, ok)
	}
	if _, _, ok, _ := g.FindClass(NAT64Class(WellKnownPrefix)); ok {
		t.Error("FindClass found a group for a class nothing serves")
	}
	if open, _ := g.AnyOpen(); !open {
		t.Error("AnyOpen = false with two open groups")
	}
	for _, id := range []uint32{0, 2} {
		if _, err := g.Close(id); err != nil {
			t.Fatal(err)
		}
	}
	if open, _ := g.AnyOpen(); open {
		t.Error("AnyOpen = true with every group closing")
	}
}

// TestClassForRoute checks which class each egress route needs.
func TestClassForRoute(t *testing.T) {
	cidr := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if c, ok := ClassForRoute(cidr("::/0")); !ok || c != NAT66Class {
		t.Errorf("::/0 -> %v %v, want nat66", c, ok)
	}
	if c, ok := ClassForRoute(cidr("64:ff9b::/96")); !ok || c != NAT64Class(WellKnownPrefix) {
		t.Errorf("64:ff9b::/96 -> %v %v, want nat64", c, ok)
	}
	if _, ok := ClassForRoute(cidr("10.0.0.0/8")); ok {
		t.Error("an IPv4 route has a translation class")
	}
}

// TestRegisterGroupWritesTheSentinel checks the sentinel layout usid.c reads.
func TestRegisterGroupWritesTheSentinel(t *testing.T) {
	tbl := NewEgressRouteTable(newFakeTable())
	if err := tbl.RegisterGroup(7, DefaultPrefix, 2, 0x2A5); err != nil {
		t.Fatal(err)
	}
	key, _ := buildKey(7, DefaultPrefix)
	value, err := lookupRaw(tbl, key)
	if err != nil {
		t.Fatal(err)
	}
	if value.LinkIfindex != 0xFFFFFFFF {
		t.Errorf("link_ifindex = %#x, want the group sentinel", value.LinkIfindex)
	}
	if got := binary.NativeEndian.Uint32(value.Sid[0:4]); got != 2 {
		t.Errorf("group id = %d, want 2", got)
	}
	if value.Sid[8] != 0x02 || value.Sid[9] != 0xA5 {
		t.Errorf("argument bytes = %#x %#x, want 0x02 0xa5", value.Sid[8], value.Sid[9])
	}
	if err := tbl.RegisterGroup(7, DefaultPrefix, MaxShardGroups, 1); err == nil {
		t.Error("RegisterGroup with an out-of-range group = nil, want an error")
	}
	if err := tbl.RegisterGroup(7, DefaultPrefix, 0, 0); err == nil {
		t.Error("RegisterGroup with Argument 0 = nil, want an error")
	}
}

// TestShardPinKeyBytesMatchesTheCLayout checks the key's size and the byte
// order of the fields the datapath copies raw from the packet.
func TestShardPinKeyBytesMatchesTheCLayout(t *testing.T) {
	key := ShardPinKey{
		TableID: 0x01020304, GroupID: 1,
		Src: netip.MustParseAddr("2001:db8::1"), Dst: netip.MustParseAddr("2001:db8::2"),
		Protocol: 6, SrcPort: 0x1234, DstPort: 0x0050,
	}
	flow := key.Bytes(HashFlow)
	if len(flow) != 44 {
		t.Fatalf("key is %d bytes, want 44 (struct egress_shard_pin_key)", len(flow))
	}
	if flow[4] != egressRouteFamilyINET6 || flow[5] != 6 || flow[6] != 1 {
		t.Errorf("family/protocol/group = %d/%d/%d, want 0/6/1", flow[4], flow[5], flow[6])
	}
	if flow[8] != 0x12 || flow[9] != 0x34 || flow[10] != 0x00 || flow[11] != 0x50 {
		t.Errorf("ports = % x, want network byte order 12 34 00 50", flow[8:12])
	}
	source := key.Bytes(HashSource)
	for i, b := range source[8:12] {
		if b != 0 {
			t.Errorf("source mode port byte %d = %#x, want 0", i, b)
		}
	}
	for i, b := range source[28:44] {
		if b != 0 {
			t.Errorf("source mode daddr byte %d = %#x, want 0", i, b)
		}
	}
	v4 := ShardPinKey{Src: netip.MustParseAddr("10.1.2.3")}.Bytes(HashSource)
	if v4[4] != egressRouteFamilyINET4 || v4[12] != 10 || v4[15] != 3 || v4[16] != 0 {
		t.Errorf("IPv4 key = % x, want family 1 and the address in the first 4 saddr bytes", v4)
	}
}

// TestGroupSnapshotSpecMatchesTheCompiledInnerMap guards the hand-written inner
// map spec against the compiled one: the kernel refuses an inner map of any
// other shape, so a drift fails every publication.
func TestGroupSnapshotSpecMatchesTheCompiledInnerMap(t *testing.T) {
	spec, err := prog.LoadUsid()
	if err != nil {
		t.Fatalf("LoadUsid: %v", err)
	}
	inner := spec.Maps[prog.UsidMapEgressShardGroups].InnerMap
	if inner == nil {
		t.Fatal("egress_shard_groups has no inner map spec")
	}
	if inner.Type != GroupSnapshotSpec.Type || inner.KeySize != GroupSnapshotSpec.KeySize ||
		inner.ValueSize != GroupSnapshotSpec.ValueSize || inner.MaxEntries != GroupSnapshotSpec.MaxEntries ||
		inner.Flags != GroupSnapshotSpec.Flags {
		t.Errorf("compiled inner map %+v, GroupSnapshotSpec %+v", inner, GroupSnapshotSpec)
	}
}
