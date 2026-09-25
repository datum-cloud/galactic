// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bond

import (
	"testing"

	"github.com/vishvananda/netlink"
)

// fakeLink is a minimal netlink.Link implementation for tests -- mirrors
// internal/plumbing/ebpf/attach's identical test fixture.
type fakeLink struct {
	attrs    netlink.LinkAttrs
	linkType string
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string {
	if f.linkType == "" {
		return "fake"
	}
	return f.linkType
}

const (
	testBondName    = "bond0"
	testNonBondName = "eth0"
)

func TestIsMaster(t *testing.T) {
	bondLink := &fakeLink{attrs: netlink.LinkAttrs{Name: testBondName}, linkType: LinkType}
	nonBondLink := &fakeLink{attrs: netlink.LinkAttrs{Name: testNonBondName}}

	if !IsMaster(bondLink) {
		t.Error("IsMaster(bond link) = false, want true")
	}
	if IsMaster(nonBondLink) {
		t.Error("IsMaster(non-bond link) = true, want false")
	}
}

func TestSlaveNames(t *testing.T) {
	const bondIndex = 10
	master := &fakeLink{attrs: netlink.LinkAttrs{Name: testBondName, Index: bondIndex}, linkType: LinkType}

	links := []netlink.Link{
		master,
		&fakeLink{attrs: netlink.LinkAttrs{Name: "slave1", Index: 11, MasterIndex: bondIndex}},
		&fakeLink{attrs: netlink.LinkAttrs{Name: "slave2", Index: 12, MasterIndex: bondIndex}},
		// Enslaved to a different master -- must never leak into the result.
		&fakeLink{attrs: netlink.LinkAttrs{Name: "unrelated-slave", Index: 13, MasterIndex: 999}},
		// Not enslaved to anything.
		&fakeLink{attrs: netlink.LinkAttrs{Name: "eth0", Index: 14}},
	}

	got := SlaveNames(master, links)
	want := []string{"slave1", "slave2"}
	if len(got) != len(want) {
		t.Fatalf("SlaveNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SlaveNames()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSlaveNames_NoSlaves(t *testing.T) {
	master := &fakeLink{attrs: netlink.LinkAttrs{Name: testBondName, Index: 10}, linkType: LinkType}
	if got := SlaveNames(master, nil); got != nil {
		t.Errorf("SlaveNames() = %v, want nil", got)
	}
}

func TestXDPTargets(t *testing.T) {
	bondLink := &fakeLink{attrs: netlink.LinkAttrs{Name: testBondName, Index: 10}, linkType: LinkType}
	nonBondLink := &fakeLink{attrs: netlink.LinkAttrs{Name: testNonBondName, Index: 2}}
	links := []netlink.Link{
		bondLink,
		nonBondLink,
		&fakeLink{attrs: netlink.LinkAttrs{Name: "eth1", Index: 3, MasterIndex: 10}},
		&fakeLink{attrs: netlink.LinkAttrs{Name: "eth2", Index: 4, MasterIndex: 10}},
	}

	tests := []struct {
		name    string
		link    netlink.Link
		links   []netlink.Link
		want    []string
		wantErr bool
	}{
		{name: "non-bond resolves to itself", link: nonBondLink, links: links, want: []string{testNonBondName}},
		{name: "bond resolves to its slaves only", link: bondLink, links: links, want: []string{"eth1", "eth2"}},
		{name: "bond with no slaves is an error", link: bondLink, links: links[:2], wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := XDPTargets(tt.link, tt.links)
			if (err != nil) != tt.wantErr {
				t.Fatalf("XDPTargets() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("XDPTargets() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("XDPTargets() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
