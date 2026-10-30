// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"fmt"
	"io"
	"io/fs"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// These tests guard issue #1270: a VRF table ID must not go to another VPC
// while node state still references it, and egress_route_table entries keyed
// by a table nothing holds must not wait for another VPC to inherit them.

const (
	vrfTablesNode = "worker-a"
	// defaultRoute is an egress_route_table prefix every fixture table holds.
	defaultRoute = "::/0"
)

// fakeEgressRoutes is an in-memory egress_route_table, by table and prefix.
type fakeEgressRoutes struct {
	rows map[uint32]map[string]struct{}
}

func newFakeEgressRoutes(rows map[uint32][]string) *fakeEgressRoutes {
	f := &fakeEgressRoutes{rows: map[uint32]map[string]struct{}{}}
	for table, prefixes := range rows {
		f.rows[table] = map[string]struct{}{}
		for _, p := range prefixes {
			f.rows[table][p] = struct{}{}
		}
	}
	return f
}

func (f *fakeEgressRoutes) Prefixes() (map[uint32]map[string]struct{}, error) {
	out := make(map[uint32]map[string]struct{}, len(f.rows))
	for table, prefixes := range f.rows {
		out[table] = map[string]struct{}{}
		for p := range prefixes {
			out[table][p] = struct{}{}
		}
	}
	return out, nil
}

func (f *fakeEgressRoutes) Unregister(table uint32, prefix *net.IPNet) error {
	delete(f.rows[table], prefix.String())
	if len(f.rows[table]) == 0 {
		delete(f.rows, table)
	}
	return nil
}

// tables returns the table IDs f holds entries for, sorted.
func (f *fakeEgressRoutes) tables() []uint32 {
	out := make([]uint32, 0, len(f.rows))
	for table := range f.rows {
		out = append(out, table)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type fakeVRFRows []usidmap.VRFEntry

func (r fakeVRFRows) List() ([]usidmap.VRFEntry, error) { return r, nil }

// vrfTablesFixture substitutes the reservations, the egress_route_table and
// the kernel VRF links sweepVRFTableState reads, and records releases.
type vrfTablesFixture struct {
	reservations []vrf.Reservation
	released     []vrf.Reservation
	egress       *fakeEgressRoutes
	now          time.Time
}

// advance moves the fixture's clock past the release grace.
func (f *vrfTablesFixture) advance() { f.now = f.now.Add(reservationReleaseGrace) }

func newVRFTablesFixture(
	t *testing.T, res []vrf.Reservation, egress map[uint32][]string, links ...*netlink.Vrf,
) *vrfTablesFixture {
	t.Helper()
	f := &vrfTablesFixture{
		reservations: res, egress: newFakeEgressRoutes(egress),
		now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	origRes, origRelease, origOpen := vrfReservationsFn, vrfReleaseFn, openEgressRoutesFn
	origNow, origSeen := nowFn, unreferenced
	t.Cleanup(func() {
		vrfReservationsFn, vrfReleaseFn, openEgressRoutesFn = origRes, origRelease, origOpen
		nowFn, unreferenced = origNow, origSeen
	})
	nowFn = func() time.Time { return f.now }
	unreferenced = &unreferencedSince{seen: map[vrf.Reservation]time.Time{}}
	vrfReservationsFn = func() ([]vrf.Reservation, error) { return f.reservations, nil }
	vrfReleaseFn = func(name string, table uint32) error {
		f.released = append(f.released, vrf.Reservation{Name: name, Table: table})
		return nil
	}
	openEgressRoutesFn = func(string) (egressRoutes, io.Closer, error) { return f.egress, io.NopCloser(nil), nil }
	withFakeLinks(t, links, nil)
	return f
}

// otherVRFName is a VRF interface name for a second VPC.
const otherVRFName = "G0000000kVV"

func TestSweepVRFTableState_ReleasesUnreferencedReservation(t *testing.T) {
	f := newVRFTablesFixture(t,
		[]vrf.Reservation{{Name: testVRFName, Table: 7}},
		map[uint32][]string{7: {defaultRoute, "2001:db8:100::/64"}, 8: {defaultRoute}},
		&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: otherVRFName}, Table: 8},
	)
	var result CleanupResult
	sweepVRFTableState(fakeVRFRows{}, "", vrfTablesNode, nil, &result)
	f.now = f.now.Add(reservationReleaseGrace - time.Second)
	sweepVRFTableState(fakeVRFRows{}, "", vrfTablesNode, nil, &result)
	if len(f.released) != 0 || len(f.egress.tables()) != 2 {
		t.Fatalf("released = %v, egress tables = %v within the grace; want nothing released or removed",
			f.released, f.egress.tables())
	}

	f.advance()
	sweepVRFTableState(fakeVRFRows{}, "", vrfTablesNode, nil, &result)
	if want := []vrf.Reservation{{Name: testVRFName, Table: 7}}; !reflect.DeepEqual(f.released, want) {
		t.Errorf("released = %v, want %v", f.released, want)
	}
	if got, want := f.egress.tables(), []uint32{8}; !reflect.DeepEqual(got, want) {
		t.Errorf("egress_route_table tables = %v, want %v: table 7's entries go before its ID is released", got, want)
	}
	if result.VRFTableReservationsReleased != 1 || result.EgressRouteTablesRemoved != 1 || result.Errors != 0 {
		t.Errorf("result = %+v, want 1 released, 1 egress table removed, no errors", result)
	}
}

func TestSweepVRFTableState_KeepsReferencedReservation(t *testing.T) {
	instName := crdnames.BGPVRFInstanceName("jU", vrfTablesNode)
	cases := []struct {
		name      string
		links     []*netlink.Vrf
		rows      fakeVRFRows
		instNames map[string]struct{}
		res       vrf.Reservation
	}{
		{
			name:  "its VRF interface exists",
			links: []*netlink.Vrf{{LinkAttrs: netlink.LinkAttrs{Name: testVRFName}, Table: 7}},
			res:   vrf.Reservation{Name: testVRFName, Table: 7},
		},
		{
			name: "a vrf_table entry still maps to its table",
			rows: fakeVRFRows{{VRFKey: usidmap.VRFKey{Block: 1, Argument: 10}, VRFTableID: 7}},
			res:  vrf.Reservation{Name: testVRFName, Table: 7},
		},
		{
			name:      "a live BGPVRFInstance names its VPC",
			instNames: map[string]struct{}{instName: {}},
			res:       vrf.Reservation{Name: testVRFName, Table: 7},
		},
		{
			name:  "another VRF holds its table",
			links: []*netlink.Vrf{{LinkAttrs: netlink.LinkAttrs{Name: otherVRFName}, Table: 7}},
			res:   vrf.Reservation{Name: testVRFName, Table: 7},
		},
		{
			name: "it is outside the host range",
			res:  vrf.Reservation{Name: testVRFName, Table: vrf.SidecarTableIDBase + 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newVRFTablesFixture(t, []vrf.Reservation{tc.res},
				map[uint32][]string{tc.res.Table: {defaultRoute}}, tc.links...)
			var result CleanupResult
			sweepVRFTableState(tc.rows, "", vrfTablesNode, tc.instNames, &result)
			f.advance()
			sweepVRFTableState(tc.rows, "", vrfTablesNode, tc.instNames, &result)
			if len(f.released) != 0 {
				t.Errorf("released = %v, want none", f.released)
			}
			if got, want := f.egress.tables(), []uint32{tc.res.Table}; !reflect.DeepEqual(got, want) {
				t.Errorf("egress_route_table tables = %v, want %v kept", got, want)
			}
			if result.Errors != 0 {
				t.Errorf("result.Errors = %d, want 0", result.Errors)
			}
		})
	}
}

func TestSweepVRFTableState_RemovesOrphanedEgressTables(t *testing.T) {
	const (
		liveTable     = 3
		reservedTable = 4
		rowTable      = 5
		orphanTable   = 6
	)
	returnTable := vrf.HostTableIDMax + 1      // the installer's sidecar return path
	sidecarTable := vrf.SidecarTableIDBase + 1 // the ingress sidecar's own range
	f := newVRFTablesFixture(t,
		[]vrf.Reservation{{Name: otherVRFName, Table: liveTable}, {Name: testVRFName, Table: reservedTable}},
		map[uint32][]string{
			liveTable: {defaultRoute}, reservedTable: {defaultRoute}, rowTable: {defaultRoute},
			orphanTable: {defaultRoute, "198.51.100.0/24"}, returnTable: {defaultRoute}, sidecarTable: {defaultRoute},
		},
		&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: otherVRFName}, Table: liveTable},
	)
	instName := crdnames.BGPVRFInstanceName("jU", vrfTablesNode)
	rows := fakeVRFRows{{VRFKey: usidmap.VRFKey{Block: 1, Argument: 10}, VRFTableID: rowTable}}

	var result CleanupResult
	sweepVRFTableState(rows, "", vrfTablesNode, map[string]struct{}{instName: {}}, &result)

	want := []uint32{liveTable, reservedTable, rowTable, returnTable, sidecarTable}
	if got := f.egress.tables(); !reflect.DeepEqual(got, want) {
		t.Errorf("egress_route_table tables = %v, want %v: only the orphaned host table goes", got, want)
	}
	if result.EgressRouteTablesRemoved != 1 || result.VRFTableReservationsReleased != 0 || result.Errors != 0 {
		t.Errorf("result = %+v, want 1 egress table removed, nothing released, no errors", result)
	}
}

func TestSweepVRFTableState_NoPinnedEgressMapIsNoOp(t *testing.T) {
	f := newVRFTablesFixture(t, []vrf.Reservation{{Name: testVRFName, Table: 7}}, nil)
	openEgressRoutesFn = func(string) (egressRoutes, io.Closer, error) {
		return nil, nil, fmt.Errorf("open pinned map: %w", fs.ErrNotExist)
	}
	var result CleanupResult
	sweepVRFTableState(fakeVRFRows{}, "", vrfTablesNode, nil, &result)
	if len(f.released) != 0 || result.Errors != 0 {
		t.Errorf("released = %v, errors = %d; want nothing released and no error", f.released, result.Errors)
	}
}

// TestSweepVRFTableState_ReferenceRestartsGrace checks that a reservation
// referenced again within the grace, as when galactic-router or the CNI
// catches up, waits a full grace from its next unreferenced sweep.
func TestSweepVRFTableState_ReferenceRestartsGrace(t *testing.T) {
	f := newVRFTablesFixture(t, []vrf.Reservation{{Name: testVRFName, Table: 7}}, map[uint32][]string{7: {defaultRoute}})
	instName := crdnames.BGPVRFInstanceName("jU", vrfTablesNode)
	var result CleanupResult

	sweepVRFTableState(fakeVRFRows{}, "", vrfTablesNode, nil, &result)
	f.advance()
	sweepVRFTableState(fakeVRFRows{}, "", vrfTablesNode, map[string]struct{}{instName: {}}, &result)
	sweepVRFTableState(fakeVRFRows{}, "", vrfTablesNode, nil, &result)
	if len(f.released) != 0 {
		t.Fatalf("released = %v right after the reservation was referenced again, want none", f.released)
	}
	f.advance()
	sweepVRFTableState(fakeVRFRows{}, "", vrfTablesNode, nil, &result)
	if want := []vrf.Reservation{{Name: testVRFName, Table: 7}}; !reflect.DeepEqual(f.released, want) {
		t.Errorf("released = %v, want %v once a full grace passed unreferenced", f.released, want)
	}
}
