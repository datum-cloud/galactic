// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"net"
	"testing"
)

// TestRefreshLeavesWorkerTenantRoutesAlone: in a table whose tenant routes
// galactic-worker keeps current, the sweep still refreshes the egress shard
// entry but leaves the tenant route alone; elsewhere it refreshes both.
func TestRefreshLeavesWorkerTenantRoutesAlone(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	tenantSID := net.ParseIP("2001:db8:ff02:9:e001::")
	shardSID := net.ParseIP("2001:db8:ff02:a:e001::")
	_, tenant, _ := net.ParseCIDR("2001:db8:a::2/128")
	const workerTable, otherTable = 1, 2
	for _, table := range []uint32{workerTable, otherTable} {
		if err := tbl.Register(table, tenant, tenantSID); err != nil {
			t.Fatal(err)
		}
		if err := tbl.Register(table, DefaultPrefix, shardSID); err != nil {
			t.Fatal(err)
		}
	}
	moved := answer{link: 1060, dmac: net.HardwareAddr{0xAA, 0, 0, 0, 0, 1}, smac: net.HardwareAddr{0xAA, 0, 0, 0, 0, 2}}
	resolverFor(t, map[string]answer{tenantSID.String(): moved, shardSID.String(): moved})

	result, err := tbl.Refresh(nil, []net.IP{shardSID},
		WithoutTenantRoutes(map[uint32]struct{}{workerTable: {}}))
	if err != nil {
		t.Fatalf("Refresh() = %v", err)
	}
	if result.Skipped != 1 || result.Refreshed != 3 {
		t.Errorf("Refresh() = %+v, want 1 skipped and 3 refreshed", result)
	}
	for _, c := range []struct {
		table uint32
		dst   *net.IPNet
		link  int
	}{
		{workerTable, tenant, fakeLinkIndex},
		{workerTable, DefaultPrefix, moved.link},
		{otherTable, tenant, moved.link},
		{otherTable, DefaultPrefix, moved.link},
	} {
		row, ok, err := tbl.LookupRow(c.table, c.dst)
		if err != nil || !ok {
			t.Fatalf("LookupRow(%d, %s) = %v, %t", c.table, c.dst, err, ok)
		}
		if row.LinkIndex != c.link {
			t.Errorf("table %d %s link = %d, want %d", c.table, c.dst, row.LinkIndex, c.link)
		}
	}
}

func TestUnregisterIfSID(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff02:9:e001::")
	other := net.ParseIP("2001:db8:ff02:a:e001::")
	_, a, _ := net.ParseCIDR("2001:db8:a::2/128")
	_, b, _ := net.ParseCIDR("2001:db8:a::3/128")
	_, pt, _ := net.ParseCIDR("2001:db8:a::4/128")
	for _, p := range []*net.IPNet{a, b} {
		if err := tbl.Register(1, p, sid); err != nil {
			t.Fatal(err)
		}
	}
	if err := tbl.RegisterPassThrough(1, pt); err != nil {
		t.Fatal(err)
	}

	if err := tbl.UnregisterIfSID(1, a, other); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := tbl.LookupRow(1, a); !ok {
		t.Error("entry toward another SID removed")
	}
	if err := tbl.UnregisterIfSID(1, a, sid); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := tbl.LookupRow(1, a); ok {
		t.Error("entry toward the SID kept")
	}
	if err := tbl.UnregisterIfSID(1, b, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := tbl.LookupRow(1, b); ok {
		t.Error("entry kept by a removal for any SID")
	}
	if err := tbl.UnregisterIfSID(1, pt, nil); err != nil {
		t.Fatal(err)
	}
	if row, ok, _ := tbl.LookupRow(1, pt); !ok || !row.PassThrough {
		t.Error("pass-through entry removed")
	}
}
