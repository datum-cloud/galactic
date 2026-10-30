// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"os"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
)

// The tap plugin keeps the owning container's ID in the alias, and DEL removes
// the tap only while it still matches, so recording host-only ports must leave
// the alias alone.
func TestRecordHostOnlyPorts_KeepsTheOwnerAlias(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root")
	}
	const name, owner = "ghotest0", "owner-container-id"
	tap := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: name}, Mode: netlink.TUNTAP_MODE_TAP}
	if err := netlink.LinkAdd(tap); err != nil {
		t.Fatalf("add tap: %v", err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(l)
		}
	})

	link := func() netlink.Link {
		t.Helper()
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("find %s: %v", name, err)
		}
		return l
	}
	if err := netlink.LinkSetAlias(link(), owner); err != nil {
		t.Fatalf("set alias: %v", err)
	}

	for _, ports := range [][]uint16{{20000}, {20000}, {20001, 20002}, nil} {
		if err := recordHostOnlyPorts(link(), ports); err != nil {
			t.Fatalf("recordHostOnlyPorts(%v): %v", ports, err)
		}
		attrs := link().Attrs()
		if attrs.Alias != owner {
			t.Errorf("after recording %v, alias = %q, want the owner %q", ports, attrs.Alias, owner)
		}
		var recorded []string
		for _, n := range attrs.AltNames {
			if _, ours, _ := ifindexvrfmap.ParseHostOnlyAltName(n); ours {
				recorded = append(recorded, n)
			}
		}
		var want []string
		if w := ifindexvrfmap.HostOnlyAltName(name, ports); w != "" {
			want = []string{w}
		}
		if !slices.Equal(recorded, want) {
			t.Errorf("after recording %v, host-only names = %v, want %v", ports, recorded, want)
		}
	}
}
