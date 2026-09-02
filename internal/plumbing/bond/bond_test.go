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

const testBondName = "bond0"

func TestIsMaster(t *testing.T) {
	bondLink := &fakeLink{attrs: netlink.LinkAttrs{Name: testBondName}, linkType: LinkType}
	nonBondLink := &fakeLink{attrs: netlink.LinkAttrs{Name: "eth0"}}

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
