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

var standbyTestNAT64 = NAT64Class(netip.MustParsePrefix("64:ff9b::/96"))

// standbyShard describes one candidate in a standby test case.
type standbyShard struct {
	sid       netip.Addr
	standby   bool
	draining  bool
	local     bool
	reachable bool
}

// wantShard is the state Apply must report, and publish, for one shard.
type wantShard struct {
	active bool
	held   bool
	// unreachable is a shard that is neither alive nor held because its SID
	// did not resolve.
	unreachable bool
}

func standbyCandidates(shards []standbyShard) (in []ShardCandidate, resolves []netip.Addr) {
	for _, s := range shards {
		in = append(in, ShardCandidate{
			SID: net.IP(s.sid.AsSlice()), Standby: s.standby, Draining: s.draining, Local: s.local,
		})
		if s.reachable {
			resolves = append(resolves, s.sid)
		}
	}
	return in, resolves
}

// TestApplyNAT64Standby checks which shards a group spreads tenants over when
// some are NAT64 standbys: a NAT64 group holds every standby out while a shard
// without the flag is alive, and a NAT66 group ignores the flag.
func TestApplyNAT64Standby(t *testing.T) {
	primary, standby, other := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	tests := []struct {
		name   string
		class  TranslationClass
		shards []standbyShard
		want   map[netip.Addr]wantShard
	}{
		{
			name:  "both up: the standby is held out of NAT64",
			class: standbyTestNAT64,
			shards: []standbyShard{
				{sid: primary, reachable: true}, {sid: standby, standby: true, reachable: true},
			},
			want: map[netip.Addr]wantShard{primary: {active: true}, standby: {held: true}},
		},
		{
			name:  "both up: NAT66 ignores the flag",
			class: NAT66Class,
			shards: []standbyShard{
				{sid: primary, reachable: true}, {sid: standby, standby: true, reachable: true},
			},
			want: map[netip.Addr]wantShard{primary: {active: true}, standby: {active: true}},
		},
		{
			name:  "primary unreachable: the standby serves NAT64",
			class: standbyTestNAT64,
			shards: []standbyShard{
				{sid: primary}, {sid: standby, standby: true, reachable: true},
			},
			want: map[netip.Addr]wantShard{primary: {unreachable: true}, standby: {active: true}},
		},
		{
			name:   "only a standby exists: it serves NAT64",
			class:  standbyTestNAT64,
			shards: []standbyShard{{sid: standby, standby: true, reachable: true}},
			want:   map[netip.Addr]wantShard{standby: {active: true}},
		},
		{
			name:  "no standby flags: unchanged",
			class: standbyTestNAT64,
			shards: []standbyShard{
				{sid: primary, reachable: true}, {sid: other, reachable: true},
			},
			want: map[netip.Addr]wantShard{primary: {active: true}, other: {active: true}},
		},
		{
			name:  "draining primary still attracts the standby's replies",
			class: standbyTestNAT64,
			shards: []standbyShard{
				{sid: primary, draining: true, reachable: true}, {sid: standby, standby: true, reachable: true},
			},
			want: map[netip.Addr]wantShard{primary: {}, standby: {held: true}},
		},
		{
			name:  "a local primary takes no tenant from here, so the standby serves",
			class: standbyTestNAT64,
			shards: []standbyShard{
				{sid: primary, local: true}, {sid: standby, standby: true, reachable: true},
			},
			want: map[netip.Addr]wantShard{primary: {}, standby: {active: true}},
		},
		{
			name:  "an unreachable standby reports unreachable, not held",
			class: standbyTestNAT64,
			shards: []standbyShard{
				{sid: primary, reachable: true}, {sid: standby, standby: true},
			},
			want: map[netip.Addr]wantShard{primary: {active: true}, standby: {unreachable: true}},
		},
		{
			name:  "one live primary of two holds the standby",
			class: standbyTestNAT64,
			shards: []standbyShard{
				{sid: primary}, {sid: other, reachable: true}, {sid: standby, standby: true, reachable: true},
			},
			want: map[netip.Addr]wantShard{primary: {unreachable: true}, other: {active: true}, standby: {held: true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeGroupStore()
			g := NewShardGroupTable(store)
			in, resolves := standbyCandidates(tt.shards)
			reachable(t, resolves...)

			result := applyOK(t, g, GroupPolicy{Class: tt.class}, in)
			v := published(t, store)
			activeSlots := map[uint8]bool{}
			for sid, want := range tt.want {
				s := slotOf(t, result, sid)
				if s.Active() != want.active || s.Held != want.held || (s.Err != nil) != want.unreachable {
					t.Errorf("%s: state %+v, want active %v held %v unreachable %v",
						sid, s, want.active, want.held, want.unreachable)
				}
				if s.Held && s.Alive {
					t.Errorf("%s: held and alive at once", sid)
				}
				flags := v.Shards[s.Slot].Flags
				if (flags&shardFlagHeld != 0) != want.held || (flags&shardFlagAlive != 0 && want.held) {
					t.Errorf("%s: published flags %#x, want held %v and never alive while held", sid, flags, want.held)
				}
				wantStandbyFlag := tt.class.NAT64 && sid == standby
				if (flags&shardFlagStandby != 0) != wantStandbyFlag {
					t.Errorf("%s: published flags %#x, want standby flag %v", sid, flags, wantStandbyFlag)
				}
				if want.active {
					activeSlots[uint8(s.Slot)] = true //nolint:gosec // < 32
				}
			}
			if int(v.Active) != len(activeSlots) || int(v.Candidates) != len(tt.shards) {
				t.Errorf("snapshot active %d candidates %d, want %d and %d",
					v.Active, v.Candidates, len(activeSlots), len(tt.shards))
			}
			for i, slot := range v.Maglev {
				if len(activeSlots) == 0 {
					if slot != shardSlotNone {
						t.Fatalf("Maglev slot %d = %d, want empty", i, slot)
					}
					continue
				}
				if !activeSlots[slot] {
					t.Fatalf("Maglev slot %d = %d, want one of the active slots %v", i, slot, activeSlots)
				}
			}
		})
	}
}

// TestApplyNAT64StandbyFollowsPrimaryLiveness checks that each Apply decides
// again: the standby serves once the primary stops resolving and is held again
// when it returns, keeping its slot and generation throughout, and that Close
// keeps the standby flag so a retired group still holds it.
func TestApplyNAT64StandbyFollowsPrimaryLiveness(t *testing.T) {
	store := newFakeGroupStore()
	g := NewShardGroupTable(store)
	primary, standby := shardSID(0x10), shardSID(0x11)
	policy := GroupPolicy{Class: standbyTestNAT64, PinIdle: time.Hour}
	in := []ShardCandidate{{SID: net.IP(primary.AsSlice())}, {SID: net.IP(standby.AsSlice()), Standby: true}}

	reachable(t, primary, standby)
	first := slotOf(t, applyOK(t, g, policy, in), standby)
	if !first.Held {
		t.Fatalf("standby %+v, want held while the primary resolves", first)
	}

	reachable(t, standby)
	failover := applyOK(t, g, policy, in)
	if s := slotOf(t, failover, standby); !s.Active() || s.Held || s.Slot != first.Slot ||
		s.Generation != first.Generation {
		t.Errorf("standby after the primary failed %+v, want active in slot %d generation %d",
			s, first.Slot, first.Generation)
	}
	if !failover.Changed {
		t.Error("losing the primary published nothing")
	}

	reachable(t, primary, standby)
	back := applyOK(t, g, policy, in)
	if s := slotOf(t, back, standby); !s.Held || s.Active() || s.Slot != first.Slot ||
		s.Generation != first.Generation {
		t.Errorf("standby after the primary returned %+v, want held in slot %d generation %d",
			s, first.Slot, first.Generation)
	}
	if back.Active() != 1 || !slotOf(t, back, primary).Active() {
		t.Errorf("after the primary returned, active = %d, want the primary alone", back.Active())
	}

	if _, err := g.Close(NAT66ShardGroup); err != nil {
		t.Fatal(err)
	}
	members, err := g.Members(NAT66ShardGroup)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if (m.SID == standby) != m.Standby || (m.SID == standby) != m.Held {
			t.Errorf("member after Close %+v: standby and held = %v, want %v", m, m.Standby, m.SID == standby)
		}
	}
}
