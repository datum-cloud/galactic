// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natattach

import (
	"errors"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/bond"
)

const (
	testUplink     = "eth0"
	testBond       = "bond0"
	testBondSlave1 = "eth1"
	testBondSlave2 = "eth2"
)

// fakeUplinkHost installs, using attach_test.go's fakeLink fixture, a netlink view holding eth0, and bond0 with slaves
// eth1 and eth2, with detection reporting detected.
func fakeUplinkHost(t *testing.T, detected []string, detectErr error) {
	t.Helper()
	origDetect, origByName, origList := detectUplinksFn, linkByNameFn, linkListFn
	t.Cleanup(func() { detectUplinksFn, linkByNameFn, linkListFn = origDetect, origByName, origList })

	links := []netlink.Link{
		&fakeLink{attrs: netlink.LinkAttrs{Name: testUplink, Index: 2}},
		&fakeLink{attrs: netlink.LinkAttrs{Name: testBond, Index: 10}, linkType: bond.LinkType},
		&fakeLink{attrs: netlink.LinkAttrs{Name: testBondSlave1, Index: 3, MasterIndex: 10}},
		&fakeLink{attrs: netlink.LinkAttrs{Name: testBondSlave2, Index: 4, MasterIndex: 10}},
	}
	detectUplinksFn = func() ([]string, error) { return detected, detectErr }
	linkByNameFn = func(name string) (netlink.Link, error) {
		for _, l := range links {
			if l.Attrs().Name == name {
				return l, nil
			}
		}
		return nil, errors.New("link not found")
	}
	linkListFn = func() ([]netlink.Link, error) { return links, nil }
}

func TestResolveUplinks(t *testing.T) {
	tests := []struct {
		name      string
		override  []string
		detected  []string
		detectErr error
		want      []string
		wantErr   bool
	}{
		{name: "auto-detected plain uplink", detected: []string{testUplink}, want: []string{testUplink}},
		{
			name:     "auto-detected bond resolves to slaves, never the master",
			detected: []string{testUplink, testBond},
			want:     []string{testUplink, testBondSlave1, testBondSlave2},
		},
		{
			name:     "override wins over detection",
			override: []string{testBond},
			detected: []string{testUplink},
			want:     []string{testBondSlave1, testBondSlave2},
		},
		{name: "override skips detection entirely", override: []string{testUplink}, detectErr: errors.New("boom"),
			want: []string{testUplink}},
		{name: "a slave named alongside its bond is not attached twice", override: []string{testBond, testBondSlave1},
			want: []string{testBondSlave1, testBondSlave2}},
		{name: "detection failure is an error", detectErr: errors.New("no routes"), wantErr: true},
		{name: "detection finding nothing is an error", detected: []string{}, wantErr: true},
		{name: "an unknown interface is an error", override: []string{"eth9"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeUplinkHost(t, tt.detected, tt.detectErr)
			got, err := ResolveUplinks(tt.override)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveUplinks(%v) error = %v, wantErr %v", tt.override, err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ResolveUplinks(%v) = %v, want %v", tt.override, got, tt.want)
			}
		})
	}
}
