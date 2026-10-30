// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/model"
)

// These tests guard issue #1270: applyVRFs resolved a VRF's kernel table once
// and reused it while the VRF stayed desired, so a VRF recreated on another
// table kept receiving its remote routes in the old one, which the node could
// give to another VPC.

const (
	movedRoutePrefix = "2001:db8:100::/64"
	movedRouteSID    = "2001:db8:f00:1::"
)

// stubVRFTable makes resolveVRFTable report *table, or err when *err is set,
// for the duration of t.
func stubVRFTable(t *testing.T, table *uint32, err *error) {
	t.Helper()
	stubVRFKernel(t, nil, nil)
	resolveVRFTable = func(string) (uint32, error) {
		if *err != nil {
			return 0, *err
		}
		return *table, nil
	}
}

// stubDelIfSID routes vrfRouteDelIfSID to f, removing an entry only while it
// still names sid.
func stubDelIfSID(t *testing.T, f *fakeEgressTable) {
	t.Helper()
	prev := vrfRouteDelIfSID
	t.Cleanup(func() { vrfRouteDelIfSID = prev })
	vrfRouteDelIfSID = func(prefix *net.IPNet, tableID uint32, sid net.IP) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		key := vrfRouteKey{tableID: tableID, prefix: mustPrefixFromIPNet(t, prefix)}
		if f.entries[key] == sid.String() {
			delete(f.entries, key)
		}
		return nil
	}
}

func movedKey(table uint32) vrfRouteKey {
	return vrfRouteKey{tableID: table, prefix: netip.MustParsePrefix(movedRoutePrefix)}
}

func (f *fakeEgressTable) put(table uint32, prefix, gw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[vrfRouteKey{tableID: table, prefix: netip.MustParsePrefix(prefix)}] = gw
}

func remoteVRFAdvertisement() model.DesiredAdvertisement {
	return model.DesiredAdvertisement{
		Name:          "remote-vpc-prefix",
		AddressFamily: model.AddressFamily{AFI: afiL2VPN, SAFI: safiEVPN},
		Prefixes:      []string{movedRoutePrefix},
		Communities:   []string{testRT100},
		NextHop:       testPeerAddr,
		SRv6SID:       movedRouteSID,
	}
}

// TestApplyVRFsFollowsRecreatedVRFTable recreates a VRF on another table while
// it stays desired, and checks that the router moves to the new table: the
// cache, the route-target index and the installed route, which leaves the old
// table.
func TestApplyVRFsFollowsRecreatedVRFTable(t *testing.T) {
	table, resolveErr := uint32(7), error(nil)
	stubVRFTable(t, &table, &resolveErr)
	f := newFakeEgressTable(t)
	f.setUsable(net.ParseIP(movedRouteSID))
	stubDelIfSID(t, f)

	r := newTestVRFRuntime(t)
	b := newTestBgpServer(t)
	ctx := context.Background()
	if err := buildEVPNPaths(b, remoteVRFAdvertisement(), "192.0.2.1", false); err != nil {
		t.Fatalf("buildEVPNPaths() error = %v", err)
	}

	if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
		t.Fatalf("first applyVRFs() error = %v", err)
	}
	if gw, ok := f.entry(movedKey(7)); !ok || gw != movedRouteSID {
		t.Fatalf("route in table 7 = %q, %v; want %s installed by the first apply", gw, ok, movedRouteSID)
	}

	table = 9 // the kernel VRF was deleted and recreated on table 9
	if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
		t.Fatalf("second applyVRFs() error = %v", err)
	}
	if got := r.appliedVRFs[testVRFName]; got != 9 {
		t.Errorf("appliedVRFs[%s] = %d, want 9", testVRFName, got)
	}
	if got := r.rtIndex[testRT100]; got != 9 {
		t.Errorf("rtIndex[%s] = %d, want 9", testRT100, got)
	}
	if gw, ok := f.entry(movedKey(9)); !ok || gw != movedRouteSID {
		t.Errorf("route in table 9 = %q, %v; want %s", gw, ok, movedRouteSID)
	}
	if gw, ok := f.entry(movedKey(7)); ok {
		t.Errorf("route in table 7 = %q, want it withdrawn from the VRF's old table", gw)
	}
}

// TestApplyVRFsKeepsAnotherWritersRouteInOldTable checks that moving a VRF off
// a table leaves an entry there that no longer names the moved VRF's SID, as
// when another VPC has since been given the table.
func TestApplyVRFsKeepsAnotherWritersRouteInOldTable(t *testing.T) {
	table, resolveErr := uint32(7), error(nil)
	stubVRFTable(t, &table, &resolveErr)
	f := newFakeEgressTable(t)
	f.setUsable(net.ParseIP(movedRouteSID))
	stubDelIfSID(t, f)

	r := newTestVRFRuntime(t)
	b := newTestBgpServer(t)
	ctx := context.Background()
	if err := buildEVPNPaths(b, remoteVRFAdvertisement(), "192.0.2.1", false); err != nil {
		t.Fatalf("buildEVPNPaths() error = %v", err)
	}
	if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
		t.Fatalf("first applyVRFs() error = %v", err)
	}

	const otherSID = "2001:db8:f00:2::"
	f.put(7, movedRoutePrefix, otherSID)
	table = 9
	if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
		t.Fatalf("second applyVRFs() error = %v", err)
	}
	if gw, ok := f.entry(movedKey(7)); !ok || gw != otherSID {
		t.Errorf("route in table 7 = %q, %v; want the other writer's %s kept", gw, ok, otherSID)
	}
}

// TestApplyVRFsKeepsTableUnlessItChanged checks that an applied VRF keeps its
// table, its route-target index entry and its routes when the re-check does
// not show a different table: the VRF is momentarily absent, a lookup fails,
// or the VRF listing itself fails. Withdrawing routes then would only cut the
// VRF's traffic; an absent VRF's table stays reserved for it.
func TestApplyVRFsKeepsTableUnlessItChanged(t *testing.T) {
	cases := []struct {
		name        string
		resolveErr  error
		snapshotErr error
	}{
		{name: "VRF momentarily absent", resolveErr: fmt.Errorf("VRF %q: %w", testVRFName, errVRFNotInThisNetns)},
		{name: "lookup fails", resolveErr: errors.New("netlink: interrupted dump")},
		{name: "VRF listing fails", snapshotErr: errors.New("netlink: interrupted dump")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table, resolveErr := uint32(7), error(nil)
			stubVRFTable(t, &table, &resolveErr)
			f := newFakeEgressTable(t)
			f.setUsable(net.ParseIP(movedRouteSID))
			stubDelIfSID(t, f)

			r := newTestVRFRuntime(t)
			b := newTestBgpServer(t)
			ctx := context.Background()
			if err := buildEVPNPaths(b, remoteVRFAdvertisement(), "192.0.2.1", false); err != nil {
				t.Fatalf("buildEVPNPaths() error = %v", err)
			}
			if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
				t.Fatalf("first applyVRFs() error = %v", err)
			}

			resolveErr = tc.resolveErr
			if tc.snapshotErr != nil {
				snapshotVRFTables = func() (func(string) (uint32, error), error) { return nil, tc.snapshotErr }
			}
			if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
				t.Fatalf("second applyVRFs() error = %v", err)
			}
			if got := r.appliedVRFs[testVRFName]; got != 7 {
				t.Errorf("appliedVRFs[%s] = %d, want 7 kept", testVRFName, got)
			}
			if got := r.rtIndex[testRT100]; got != 7 {
				t.Errorf("rtIndex[%s] = %d, want 7 kept", testRT100, got)
			}
			if gw, ok := f.entry(movedKey(7)); !ok || gw != movedRouteSID {
				t.Errorf("route in table 7 = %q, %v; want it kept", gw, ok)
			}
		})
	}
}
