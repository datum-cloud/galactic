// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// TestSyncHostLinkRoutes: the edge's pass-through entries in one table end up
// exactly the wanted prefixes, over a previous holder's encapsulating entry,
// while another owner's pass-through, an unwanted encapsulating entry and
// another table's entries are left alone.
func TestSyncHostLinkRoutes(t *testing.T) {
	restore := egressroutemap.OverrideResolverForTest(func(net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		return 2, net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, nil
	})
	defer restore()
	const vrfTable = 1001
	table := egressroutemap.NewEgressRouteTable(memTable{})
	workload := netip.MustParsePrefix("fd20:1::/64")
	stale := netip.MustParsePrefix("fd00:aa::9/128")
	remote := netip.MustParsePrefix("fd00:aa:0:f::/80")
	elsewhere := netip.MustParsePrefix("fd00:cc::/64")
	sid := net.ParseIP("2001:db8:ff01:9:e001::")
	if err := table.RegisterPassThrough(vrfTable, prefixIPNet(workload)); err != nil {
		t.Fatal(err)
	}
	if err := table.RegisterPassThroughAs(vrfTable, prefixIPNet(stale), egressroutemap.PassThroughEdge); err != nil {
		t.Fatal(err)
	}
	for _, p := range []netip.Prefix{remote, elsewhere} {
		if err := table.Register(vrfTable, prefixIPNet(p), sid); err != nil {
			t.Fatal(err)
		}
	}
	if err := table.RegisterPassThroughAs(vrfTable+1, prefixIPNet(stale), egressroutemap.PassThroughEdge); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParsePrefix("fd00:aa::1/128")
	if err := syncHostLinkRoutesIn(table, vrfTable, []netip.Prefix{addr, remote, workload}); err != nil {
		t.Fatal(err)
	}
	edge := egressroutemap.Entry{PassThrough: true, Owner: egressroutemap.PassThroughEdge}
	want := map[netip.Prefix]egressroutemap.Entry{
		addr:      edge,
		remote:    edge,
		workload:  {PassThrough: true, Owner: egressroutemap.PassThroughCNI},
		elsewhere: {PassThrough: false},
	}
	got, err := table.Entries(vrfTable)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("entries %v, want %v", got, want)
	}
	for p, w := range want {
		if g, ok := got[p]; !ok || g.PassThrough != w.PassThrough || (w.PassThrough && g.Owner != w.Owner) {
			t.Errorf("entry %s = %+v (%t), want %+v", p, g, ok, w)
		}
	}
	if other, _ := table.Entries(vrfTable + 1); len(other) != 1 {
		t.Errorf("other table's entries %v, want its edge entry kept", other)
	}

	// Nothing wanted: every edge entry goes, and nothing else.
	if err := syncHostLinkRoutesIn(table, vrfTable, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = table.Entries(vrfTable)
	if _, ok := got[addr]; ok || len(got) != 2 {
		t.Errorf("entries after an empty sync %v, want only the workload and encapsulating entries", got)
	}
}
