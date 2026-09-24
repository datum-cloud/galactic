// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import (
	"maps"
	"testing"
)

func TestStableSlots(t *testing.T) {
	tests := []struct {
		name      string
		uplinks   []uint32
		current   map[uint32]uint8
		want      map[uint32]uint8
		wantError bool
	}{
		{"Fresh", []uint32{7, 3}, nil, map[uint32]uint8{3: 0, 7: 1}, false},
		{"KeepsExisting", []uint32{3, 7}, map[uint32]uint8{7: 5}, map[uint32]uint8{7: 5, 3: 0}, false},
		{"AvoidsReleased", []uint32{9}, map[uint32]uint8{3: 0}, map[uint32]uint8{9: 1}, false},
		{"DropsRemoved", []uint32{3}, map[uint32]uint8{3: 2, 4: 0}, map[uint32]uint8{3: 2}, false},
		{"DuplicateUplink", []uint32{3, 3}, nil, map[uint32]uint8{3: 0}, false},
		{"TooMany", seq(MaxSlots + 1), nil, nil, true},
		{"Full", seq(MaxSlots), nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StableSlots(tt.uplinks, tt.current)
			if (err != nil) != tt.wantError {
				t.Fatalf("StableSlots() error = %v, wantError %v", err, tt.wantError)
			}
			if tt.want != nil && !maps.Equal(got, tt.want) {
				t.Errorf("StableSlots() = %v, want %v", got, tt.want)
			}
			seen := map[uint8]bool{}
			for _, s := range got {
				if seen[s] || int(s) >= MaxSlots {
					t.Errorf("slot %d duplicated or out of range in %v", s, got)
				}
				seen[s] = true
			}
		})
	}
}

func TestStableSlotsReusesReleasedWhenFull(t *testing.T) {
	current := map[uint32]uint8{}
	for i := range uint32(MaxSlots) {
		current[i+1] = uint8(i)
	}
	uplinks := seq(MaxSlots)
	uplinks[0] = 1000
	got, err := StableSlots(uplinks, current)
	if err != nil {
		t.Fatal(err)
	}
	if got[1000] != 0 {
		t.Errorf("new uplink got slot %d, want released slot 0", got[1000])
	}
}

func TestKeepSlots(t *testing.T) {
	cur := map[uint32]uint8{4: 2}
	got, err := KeepSlots([]uint32{1, 2}, cur)
	if err != nil || !maps.Equal(got, cur) {
		t.Errorf("KeepSlots() = %v, %v", got, err)
	}
}

func seq(n int) []uint32 {
	out := make([]uint32, n)
	for i := range out {
		out[i] = uint32(i + 1)
	}
	return out
}
