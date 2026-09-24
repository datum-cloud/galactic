// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import (
	"fmt"
	"maps"
	"slices"
)

// StableSlots is a SlotAssigner that keeps every uplink still present on the
// slot it already holds and gives each new uplink the lowest free slot. A slot
// released in this same pass is reused only when no other is free, so an entry
// still naming the old uplink's bit is not briefly accepted on the new one. More
// than MaxSlots uplinks is an error.
func StableSlots(uplinks []uint32, current map[uint32]uint8) (map[uint32]uint8, error) {
	want := make(map[uint32]struct{}, len(uplinks))
	for _, ifindex := range uplinks {
		want[ifindex] = struct{}{}
	}
	if len(want) > MaxSlots {
		return nil, fmt.Errorf("%d uplinks exceed the source filter's %d interface slots", len(want), MaxSlots)
	}

	out := make(map[uint32]uint8, len(want))
	var used, released [MaxSlots]bool
	for ifindex, slot := range current {
		if int(slot) >= MaxSlots {
			continue
		}
		if _, ok := want[ifindex]; ok && !used[slot] {
			out[ifindex] = slot
			used[slot] = true
			continue
		}
		released[slot] = true
	}

	pick := func() uint8 {
		for _, avoidReleased := range []bool{true, false} {
			for s := range MaxSlots {
				if !used[s] && (!avoidReleased || !released[s]) {
					used[s] = true
					return uint8(s)
				}
			}
		}
		return MaxSlots
	}
	for _, ifindex := range slices.Sorted(maps.Keys(want)) {
		if _, ok := out[ifindex]; ok {
			continue
		}
		out[ifindex] = pick()
	}
	return out, nil
}

// KeepSlots is a SlotAssigner for a datapath whose owner assigns uplink slots
// itself: it returns the Target's current assignment unchanged.
func KeepSlots(_ []uint32, current map[uint32]uint8) (map[uint32]uint8, error) {
	return maps.Clone(current), nil
}
