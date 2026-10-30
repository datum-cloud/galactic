// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vrf

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/vishvananda/netlink"
)

// These tests guard issue #1270: a VRF recreated on a node took the lowest
// free table ID, so its old ID went to the next VPC created, which inherited
// the vrf_table, egress_route_table and galactic-router state still keyed by
// it.

// useReservationsDir points the reservation file at a temporary directory and
// the link listing at links, for the duration of t.
func useReservationsDir(t *testing.T, links ...*netlink.Vrf) string {
	t.Helper()
	dir := t.TempDir()
	origDir, origList := reservationsDir, listVRFLinksFn
	t.Cleanup(func() { reservationsDir, listVRFLinksFn = origDir, origList })
	reservationsDir = dir
	listVRFLinksFn = func() ([]*netlink.Vrf, error) { return links, nil }
	return dir
}

func vrfLink(name string, table uint32) *netlink.Vrf {
	return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: name}, Table: table}
}

func sortedReservations(res []Reservation) []Reservation {
	out := append([]Reservation(nil), res...)
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out
}

func TestReserveTable(t *testing.T) {
	cases := []struct {
		name      string
		res       []Reservation
		live      map[uint32]string
		vrf       string
		min, max  uint32
		wantTable uint32
		wantRes   []Reservation
	}{
		{
			name: "a recreated VRF gets its reserved table back",
			res:  []Reservation{{Name: "GA", Table: 1}, {Name: "GB", Table: 2}},
			live: map[uint32]string{2: "GB"},
			vrf:  "GA", min: 1, max: 100,
			wantTable: 1,
			wantRes:   []Reservation{{Name: "GA", Table: 1}, {Name: "GB", Table: 2}},
		},
		{
			name: "a new VRF never takes a table another VRF has reserved",
			res:  []Reservation{{Name: "GA", Table: 1}},
			live: map[uint32]string{},
			vrf:  "GB", min: 1, max: 100,
			wantTable: 2,
			wantRes:   []Reservation{{Name: "GA", Table: 1}, {Name: "GB", Table: 2}},
		},
		{
			name: "a new VRF skips live tables as well as reserved ones",
			res:  []Reservation{{Name: "GA", Table: 2}},
			live: map[uint32]string{1: "GX"},
			vrf:  "GB", min: 1, max: 100,
			wantTable: 3,
			wantRes:   []Reservation{{Name: "GA", Table: 2}, {Name: "GB", Table: 3}},
		},
		{
			name: "a reserved table another live VRF holds is given up",
			res:  []Reservation{{Name: "GA", Table: 1}},
			live: map[uint32]string{1: "GX"},
			vrf:  "GA", min: 1, max: 100,
			wantTable: 2,
			wantRes:   []Reservation{{Name: "GA", Table: 2}},
		},
		{
			name: "a reservation in another range is neither reused nor in the way",
			res:  []Reservation{{Name: "GA", Table: SidecarTableIDBase + 1}},
			live: map[uint32]string{},
			vrf:  "GA", min: HostTableIDMin, max: HostTableIDMax,
			wantTable: 1,
			wantRes:   []Reservation{{Name: "GA", Table: 1}, {Name: "GA", Table: SidecarTableIDBase + 1}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table, res, err := reserveTable(tc.res, tc.live, tc.vrf, tc.min, tc.max)
			if err != nil {
				t.Fatalf("reserveTable() error = %v", err)
			}
			if table != tc.wantTable {
				t.Errorf("table = %d, want %d", table, tc.wantTable)
			}
			if got, want := sortedReservations(res), sortedReservations(tc.wantRes); !reflect.DeepEqual(got, want) {
				t.Errorf("reservations = %v, want %v", got, want)
			}
		})
	}
}

func TestReserveTable_FullRange(t *testing.T) {
	res := []Reservation{{Name: "GA", Table: 10}}
	if _, _, err := reserveTable(res, map[uint32]string{11: "GB"}, "GC", 10, 11); err == nil {
		t.Fatal("reserveTable() error = nil, want an error with every table reserved or live")
	}
}

func TestRecordTable(t *testing.T) {
	cases := []struct {
		name        string
		res         []Reservation
		wantRes     []Reservation
		wantChanged bool
	}{
		{
			name:        "already recorded",
			res:         []Reservation{{Name: "GA", Table: 5}},
			wantRes:     []Reservation{{Name: "GA", Table: 5}},
			wantChanged: false,
		},
		{
			name:        "unrecorded VRF from before reservations",
			res:         nil,
			wantRes:     []Reservation{{Name: "GA", Table: 5}},
			wantChanged: true,
		},
		{
			name:        "the live link replaces a different reservation of its own",
			res:         []Reservation{{Name: "GA", Table: 3}},
			wantRes:     []Reservation{{Name: "GA", Table: 5}},
			wantChanged: true,
		},
		{
			name:        "the live link takes its table from another VRF's reservation",
			res:         []Reservation{{Name: "GB", Table: 5}},
			wantRes:     []Reservation{{Name: "GA", Table: 5}},
			wantChanged: true,
		},
		{
			name:        "a reservation in another range is kept",
			res:         []Reservation{{Name: "GA", Table: SidecarTableIDBase + 1}},
			wantRes:     []Reservation{{Name: "GA", Table: 5}, {Name: "GA", Table: SidecarTableIDBase + 1}},
			wantChanged: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, changed := recordTable(tc.res, "GA", 5, HostTableIDMin, HostTableIDMax)
			if changed != tc.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tc.wantChanged)
			}
			if got, want := sortedReservations(res), sortedReservations(tc.wantRes); !reflect.DeepEqual(got, want) {
				t.Errorf("reservations = %v, want %v", got, want)
			}
		})
	}
}

func TestReleaseLocked(t *testing.T) {
	useReservationsDir(t)
	if err := saveReservations([]Reservation{{Name: "GA", Table: 1}, {Name: "GB", Table: 2}}); err != nil {
		t.Fatalf("saveReservations() error = %v", err)
	}

	// A name and table that do not match one reservation release nothing.
	if err := ReleaseLocked("GA", 2); err != nil {
		t.Fatalf("ReleaseLocked(GA, 2) error = %v", err)
	}
	if err := ReleaseLocked("GA", 1); err != nil {
		t.Fatalf("ReleaseLocked(GA, 1) error = %v", err)
	}
	got, err := ReservationsLocked()
	if err != nil {
		t.Fatalf("ReservationsLocked() error = %v", err)
	}
	if want := []Reservation{{Name: "GB", Table: 2}}; !reflect.DeepEqual(got, want) {
		t.Errorf("reservations = %v, want %v", got, want)
	}

	// Once released, the table is free for another VRF.
	table, _, err := reserveTable(got, map[uint32]string{}, "GC", 1, 100)
	if err != nil || table != 1 {
		t.Errorf("reserveTable() = %d, %v; want 1, nil", table, err)
	}
}

func TestLoadReservations_RebuildsFromLiveVRFs(t *testing.T) {
	want := []Reservation{{Name: "GA", Table: 4}, {Name: "GB", Table: 9}}

	t.Run("missing file", func(t *testing.T) {
		useReservationsDir(t, vrfLink("GA", 4), vrfLink("GB", 9))
		got, err := loadReservations()
		if err != nil {
			t.Fatalf("loadReservations() error = %v", err)
		}
		if !reflect.DeepEqual(sortedReservations(got), want) {
			t.Errorf("reservations = %v, want %v", got, want)
		}
	})

	t.Run("corrupt file", func(t *testing.T) {
		dir := useReservationsDir(t, vrfLink("GA", 4), vrfLink("GB", 9))
		if err := os.WriteFile(filepath.Join(dir, reservationsFileName), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadReservations()
		if err != nil {
			t.Fatalf("loadReservations() error = %v", err)
		}
		if !reflect.DeepEqual(sortedReservations(got), want) {
			t.Errorf("reservations = %v, want %v", got, want)
		}
	})

	t.Run("unknown version", func(t *testing.T) {
		dir := useReservationsDir(t, vrfLink("GA", 4), vrfLink("GB", 9))
		data := []byte(`{"version":99,"tables":[{"name":"GZ","table":1}]}`)
		if err := os.WriteFile(filepath.Join(dir, reservationsFileName), data, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadReservations()
		if err != nil {
			t.Fatalf("loadReservations() error = %v", err)
		}
		if !reflect.DeepEqual(sortedReservations(got), want) {
			t.Errorf("reservations = %v, want %v", got, want)
		}
	})
}

func TestSaveReservations_RoundTrip(t *testing.T) {
	dir := useReservationsDir(t)
	in := []Reservation{{Name: "GB", Table: 7}, {Name: "GA", Table: 3}}
	if err := saveReservations(in); err != nil {
		t.Fatalf("saveReservations() error = %v", err)
	}
	got, err := loadReservations()
	if err != nil {
		t.Fatalf("loadReservations() error = %v", err)
	}
	if want := []Reservation{{Name: "GA", Table: 3}, {Name: "GB", Table: 7}}; !reflect.DeepEqual(got, want) {
		t.Errorf("reservations = %v, want %v", got, want)
	}
	tables, err := ReservedTables()
	if err != nil {
		t.Fatalf("ReservedTables() error = %v", err)
	}
	if want := map[uint32]struct{}{3: {}, 7: {}}; !reflect.DeepEqual(tables, want) {
		t.Errorf("ReservedTables() = %v, want %v", tables, want)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != reservationsFileName {
		t.Errorf("directory holds %v, want only %s: a temporary file was left behind", entries, reservationsFileName)
	}
}

func TestReleaseNameLocked_OnlyInRange(t *testing.T) {
	useReservationsDir(t)
	sidecar := SidecarTableIDBase + 1
	in := []Reservation{{Name: "GA", Table: 3}, {Name: "GA", Table: sidecar}, {Name: "GB", Table: sidecar + 1}}
	if err := saveReservations(in); err != nil {
		t.Fatalf("saveReservations() error = %v", err)
	}
	if err := releaseNameLocked("GA", SidecarTableIDBase, SidecarTableIDBase+0xFFF); err != nil {
		t.Fatalf("releaseNameLocked() error = %v", err)
	}
	got, err := ReservationsLocked()
	if err != nil {
		t.Fatalf("ReservationsLocked() error = %v", err)
	}
	if want := []Reservation{{Name: "GA", Table: 3}, {Name: "GB", Table: sidecar + 1}}; !reflect.DeepEqual(got, want) {
		t.Errorf("reservations = %v, want %v: only GA's reservation in the sidecar range goes", got, want)
	}
}
