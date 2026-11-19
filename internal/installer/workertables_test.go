// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"errors"
	"net"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// workerTables makes the sweep see tables, or err, as the tables whose tenant
// routes galactic-worker owns.
func workerTables(t *testing.T, tables map[uint32]struct{}, err error) {
	t.Helper()
	prev := workerTenantTablesFn
	workerTenantTablesFn = func() (map[uint32]struct{}, error) { return tables, err }
	t.Cleanup(func() { workerTenantTablesFn = prev })
}

func TestSweepLeavesWorkerTenantRoutesAlone(t *testing.T) {
	f := newFixture(t, testOrdered, []string{shardSIDFor(0x10)}, nil)
	_, tenant, _ := net.ParseCIDR("2001:db8:a::2/128")
	sid := net.ParseIP(shardSIDFor(0x20)) // a remote node, not a shard
	for _, table := range []uint32{1, 2} {
		if err := f.routes.Register(table, tenant, sid); err != nil {
			t.Fatal(err)
		}
	}
	workerTables(t, map[uint32]struct{}{1: {}}, nil)
	restore := egressroutemap.OverrideResolverForTest(func(net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		return 9, net.HardwareAddr{2, 0, 0, 0, 0, 9}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, nil
	})
	t.Cleanup(restore)

	if err := f.sweep(t); err != nil {
		t.Fatalf("sweep = %v", err)
	}
	for table, want := range map[uint32]int{1: 7, 2: 9} {
		row, ok, err := f.routes.LookupRow(table, tenant)
		if err != nil || !ok || row.LinkIndex != want {
			t.Errorf("table %d tenant route = %+v (%t, %v), want link %d", table, row, ok, err, want)
		}
	}
}

func TestSweepSkippedWhenWorkerOwnershipIsUnreadable(t *testing.T) {
	f := newFixture(t, testOrdered, []string{shardSIDFor(0x10)}, nil)
	_, tenant, _ := net.ParseCIDR("2001:db8:a::2/128")
	if err := f.routes.Register(1, tenant, net.ParseIP(shardSIDFor(0x20))); err != nil {
		t.Fatal(err)
	}
	errFence := errors.New("fence unreadable")
	workerTables(t, nil, errFence)
	restore := egressroutemap.OverrideResolverForTest(func(net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		return 9, net.HardwareAddr{2, 0, 0, 0, 0, 9}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, nil
	})
	t.Cleanup(restore)

	if err := f.sweep(t); !errors.Is(err, errFence) {
		t.Fatalf("sweep = %v, want the fence error", err)
	}
	if row, _, _ := f.routes.LookupRow(1, tenant); row.LinkIndex != 7 {
		t.Errorf("tenant route rewritten to link %d by a sweep that could not read ownership", row.LinkIndex)
	}
}
