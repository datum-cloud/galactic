// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// TestUnregisterPassThroughAs_KernelTrie runs owner-scoped removal against a
// real egress_route_table trie, whose lookups are longest-prefix: an entry
// with no key of its own answers through a shorter one, which is never
// deleted, and an encapsulating entry for the key is kept.
func TestUnregisterPassThroughAs_KernelTrie(t *testing.T) {
	requireRoot(t)
	stubResolveLinkAndL2(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := prog.LoadUsid()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(spec.Maps[prog.UsidMapEgressRouteTable].Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	tbl := NewEgressRouteTable(usidmap.KernelTable{Map: m})

	short, host, encap := mustCIDR(t, "fd00:aa::/64"), mustCIDR(t, "fd00:aa::1/128"), mustCIDR(t, "fd00:bb::1/128")
	if err := tbl.RegisterPassThroughAs(7, short, PassThroughEdge); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Register(7, encap, net.ParseIP("2001:db8:ff01:9:e001::")); err != nil {
		t.Fatal(err)
	}

	for _, p := range []*net.IPNet{host, encap} {
		if removed, err := tbl.UnregisterPassThroughAs(7, p, PassThroughEdge); err != nil || removed {
			t.Errorf("UnregisterPassThroughAs(%s) = %t, %v; want nothing removed", p, removed, err)
		}
	}
	if entries, err := tbl.Entries(7); err != nil || len(entries) != 2 {
		t.Fatalf("entries %v (%v), want the /64 and the encapsulating entry kept", entries, err)
	}

	if err := tbl.RegisterPassThroughAs(7, host, PassThroughEdge); err != nil {
		t.Fatal(err)
	}
	if removed, err := tbl.UnregisterPassThroughAs(7, host, PassThroughEdge); err != nil || !removed {
		t.Fatalf("UnregisterPassThroughAs(%s) = %t, %v; want removed", host, removed, err)
	}
	if entries, _ := tbl.Entries(7); len(entries) != 2 {
		t.Errorf("entries %v after removing the /128, want the /64 and the encapsulating entry", entries)
	}
}
