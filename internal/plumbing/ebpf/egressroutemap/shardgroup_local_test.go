// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func localCandidates(local netip.Addr, others ...netip.Addr) []ShardCandidate {
	out := make([]ShardCandidate, 0, 1+len(others))
	out = append(out, ShardCandidate{SID: net.IP(local.AsSlice()), Local: true})
	for _, o := range others {
		out = append(out, ShardCandidate{SID: net.IP(o.AsSlice())})
	}
	return out
}

// TestApplyBaseViewUnchangedByLocalView checks the coordinator's guard from
// the Go side: a table that also publishes local views publishes the same
// base view, byte for byte, as one that does not.
func TestApplyBaseViewUnchangedByLocalView(t *testing.T) {
	local, a, b := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachable(t, a, b)
	policy := GroupPolicy{PinIdle: time.Hour}

	plainStore := newFakeGroupStore()
	plain := NewShardGroupTable(plainStore)
	baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
	withLocal := NewShardGroupTable(baseStore).WithLocalView(localStore)

	for _, in := range [][]ShardCandidate{
		localCandidates(local, a, b),
		localCandidates(local, a),
		{{SID: net.IP(a.AsSlice())}},
		localCandidates(local, a, b),
	} {
		applyOK(t, plain, policy, in)
		applyOK(t, withLocal, policy, in)
		if published(t, plainStore) != published(t, baseStore) {
			t.Fatalf("base view differs with a local view store for candidates %v", in)
		}
	}
}

func TestApplyLocalViewMakesTheLocalShardAlive(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachable(t, remote)
	baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
	g := NewShardGroupTable(baseStore).WithLocalView(localStore)

	result := applyOK(t, g, GroupPolicy{PinIdle: time.Hour}, localCandidates(local, remote))
	if !result.LocalView || !result.LocalChanged {
		t.Fatalf("result %+v, want a local view published", result)
	}
	base, view := published(t, baseStore), published(t, localStore)
	ls, rs := slotOf(t, result, local).Slot, slotOf(t, result, remote).Slot

	if f := base.Shards[ls].Flags; f != shardFlagLocal {
		t.Errorf("base view local flags %#x, want local only", f)
	}
	if f := view.Shards[ls].Flags; f != shardFlagLocal|shardFlagAlive {
		t.Errorf("local view local flags %#x, want local and alive", f)
	}
	if m := view.Shards[ls]; m.LinkIfindex != 0 || m.Dmac != [6]byte{} || m.Smac != [6]byte{} {
		t.Errorf("local view local member %+v carries a next hop", m)
	}
	if view.Shards[rs] != base.Shards[rs] {
		t.Errorf("remote member differs: base %+v, local view %+v", base.Shards[rs], view.Shards[rs])
	}
	for i := range base.Shards {
		if base.Shards[i].Generation != view.Shards[i].Generation || base.Shards[i].Sid != view.Shards[i].Sid {
			t.Errorf("slot %d: base %+v and local view %+v hold different shards or generations",
				i, base.Shards[i], view.Shards[i])
		}
	}
	if view.NextSlotGeneration != base.NextSlotGeneration || view.ClassKind != base.ClassKind ||
		view.PinIdleSec != base.PinIdleSec {
		t.Errorf("local view header %+v differs from base %+v", view, base)
	}
	seen := map[uint8]int{}
	for _, s := range view.Maglev {
		seen[s]++
	}
	if seen[uint8(ls)] == 0 || seen[uint8(rs)] == 0 || len(seen) != 2 { //nolint:gosec // < 32
		t.Errorf("local view Maglev spread %v, want both shards and nothing else", seen)
	}
	if view.Active != 2 || base.Active != 1 {
		t.Errorf("active: local view %d, base %d; want 2 and 1", view.Active, base.Active)
	}
}

func TestApplyLocalViewDrainingLocalKeepsPinsTakesNoTenant(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachable(t, remote)
	baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
	g := NewShardGroupTable(baseStore).WithLocalView(localStore)

	in := localCandidates(local, remote)
	in[0].Draining = true
	result := applyOK(t, g, GroupPolicy{PinIdle: time.Hour}, in)
	view := published(t, localStore)
	ls := slotOf(t, result, local).Slot
	if f := view.Shards[ls].Flags; f != shardFlagLocal|shardFlagAlive|shardFlagDraining {
		t.Errorf("draining local flags %#x, want local, alive and draining", f)
	}
	for i, s := range view.Maglev {
		if int(s) == ls {
			t.Fatalf("Maglev slot %d names the draining local shard", i)
		}
	}
}

func TestApplyLocalViewStandbyHold(t *testing.T) {
	class := NAT64Class(WellKnownPrefix)
	policy := GroupPolicy{Class: class, PinIdle: time.Hour}

	t.Run("local primary holds a remote standby", func(t *testing.T) {
		local, standby := shardSID(0x10), shardSID(0x11)
		reachable(t, standby)
		baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
		g := NewShardGroupTable(baseStore).WithLocalView(localStore)
		in := localCandidates(local, standby)
		in[1].Standby = true
		result := applyOK(t, g, policy, in)
		ss := slotOf(t, result, standby).Slot
		if f := published(t, baseStore).Shards[ss].Flags; f&shardFlagAlive == 0 || f&shardFlagHeld != 0 {
			t.Errorf("base view standby flags %#x, want alive: no primary resolves here", f)
		}
		if f := published(t, localStore).Shards[ss].Flags; f&shardFlagHeld == 0 || f&shardFlagAlive != 0 {
			t.Errorf("local view standby flags %#x, want held behind the local primary", f)
		}
	})
	t.Run("remote primary holds a local standby", func(t *testing.T) {
		local, primary := shardSID(0x10), shardSID(0x11)
		reachable(t, primary)
		baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
		g := NewShardGroupTable(baseStore).WithLocalView(localStore)
		in := localCandidates(local, primary)
		in[0].Standby = true
		result := applyOK(t, g, policy, in)
		ls := slotOf(t, result, local).Slot
		if f := published(t, localStore).Shards[ls].Flags; f&shardFlagHeld == 0 || f&shardFlagAlive != 0 {
			t.Errorf("local view local standby flags %#x, want held", f)
		}
	})
	t.Run("NAT66 ignores standby", func(t *testing.T) {
		local, other := shardSID(0x10), shardSID(0x11)
		reachable(t, other)
		baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
		g := NewShardGroupTable(baseStore).WithLocalView(localStore)
		in := localCandidates(local, other)
		in[1].Standby = true
		result := applyOK(t, g, GroupPolicy{}, in)
		if f := published(t, localStore).Shards[slotOf(t, result, other).Slot].Flags; f != shardFlagAlive {
			t.Errorf("NAT66 standby flags %#x, want alive only", f)
		}
	})
}

func TestApplyLocalViewDisabledWithoutLocalCandidate(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachable(t, remote)
	baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
	g := NewShardGroupTable(baseStore).WithLocalView(localStore)

	remoteOnly := []ShardCandidate{{SID: net.IP(remote.AsSlice())}}
	if r := applyOK(t, g, GroupPolicy{}, remoteOnly); r.LocalView || r.LocalChanged {
		t.Fatalf("result %+v, want no local view and nothing published", r)
	}
	if len(localStore.attempts) != 0 {
		t.Fatalf("local view published %d times with no local candidate ever", len(localStore.attempts))
	}
	applyOK(t, g, GroupPolicy{}, localCandidates(local, remote))
	gen := published(t, localStore).Generation
	r := applyOK(t, g, GroupPolicy{}, []ShardCandidate{{SID: net.IP(remote.AsSlice())}})
	if r.LocalView || !r.LocalChanged {
		t.Fatalf("result %+v, want the local view disabled", r)
	}
	v := published(t, localStore)
	if v.Flags&groupFlagEnabled != 0 || v.Generation != gen+1 {
		t.Errorf("local view %+v, want disabled at generation %d", v, gen+1)
	}
	if r := applyOK(t, g, GroupPolicy{}, []ShardCandidate{{SID: net.IP(remote.AsSlice())}}); r.LocalChanged {
		t.Error("a second Apply republished the disabled local view")
	}
}

func TestApplyLocalViewUnchangedIsNotRepublished(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachable(t, remote)
	baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
	g := NewShardGroupTable(baseStore).WithLocalView(localStore)
	applyOK(t, g, GroupPolicy{}, localCandidates(local, remote))
	n := len(localStore.attempts)
	if r := applyOK(t, g, GroupPolicy{}, localCandidates(local, remote)); r.LocalChanged || r.Changed {
		t.Errorf("result %+v, want nothing republished", r)
	}
	if len(localStore.attempts) != n {
		t.Error("local view republished with nothing changed")
	}
}

func TestDisableAndCloseCoverTheLocalView(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachable(t, remote)
	baseStore, localStore := newFakeGroupStore(), newFakeGroupStore()
	g := NewShardGroupTable(baseStore).WithLocalView(localStore)
	applyOK(t, g, GroupPolicy{}, localCandidates(local, remote))

	if _, err := g.Close(NAT66ShardGroup); err != nil {
		t.Fatal(err)
	}
	if v := published(t, localStore); v.Flags&groupFlagClosing == 0 || v.Flags&groupFlagEnabled == 0 {
		t.Errorf("local view after Close flags %#x, want enabled and closing", v.Flags)
	}
	if changed, err := g.Disable(NAT66ShardGroup); err != nil || !changed {
		t.Fatalf("Disable = %t, %v", changed, err)
	}
	base, view := published(t, baseStore), published(t, localStore)
	if base.Flags&groupFlagEnabled != 0 || view.Flags&groupFlagEnabled != 0 {
		t.Errorf("after Disable base flags %#x, local view flags %#x; want both disabled", base.Flags, view.Flags)
	}
	if view.NextSlotGeneration < base.NextSlotGeneration {
		t.Errorf("local view generation counter %d below base %d", view.NextSlotGeneration, base.NextSlotGeneration)
	}
}
