// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"net"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// tenantLocatorBlock stands in for the real, locator-derived Block a tenant CNI
// attachment registers its VRF under, the population the host does own.
const tenantLocatorBlock = uint64(0x2001_0db8_ff02)

// hostOwnedTable and sidecarOwnedTable are one routing table ID from each
// namespace. Each namespace allocates from 1 upward without seeing the other,
// so the number alone says nothing about who wrote an entry keyed on it.
const (
	hostOwnedTable    = uint32(1)
	sidecarOwnedTable = uint32(2)
)

// vrfTableWith returns a vrf_table holding one row per (block, tableID) pair,
// the registrations the two writers make before installing any egress route.
func vrfTableWith(t *testing.T, rows map[uint32]uint64) *usidmap.VRFTable {
	t.Helper()
	vrfTable := usidmap.NewVRFTable(newFakeTable())
	for tableID, block := range rows {
		if err := vrfTable.Register(block, uint16(tableID), tableID, usidmap.EgressKindVeth); err != nil {
			t.Fatalf("vrf_table Register(block=%#x table=%d) = %v, want success", block, tableID, err)
		}
	}
	return vrfTable
}

// TestSidecarOwnedTableIDsSelectsOnlyTheReservedBlock proves the host can tell
// the two writers apart from state they already publish, with no second copy of
// the ownership record.
func TestSidecarOwnedTableIDsSelectsOnlyTheReservedBlock(t *testing.T) {
	vrfTable := vrfTableWith(t, map[uint32]uint64{
		hostOwnedTable:    tenantLocatorBlock,
		sidecarOwnedTable: uformat.BlockIngressSidecar,
	})

	owned, err := SidecarOwnedTableIDs(vrfTable)
	if err != nil {
		t.Fatalf("SidecarOwnedTableIDs = %v, want success", err)
	}
	if _, ok := owned[sidecarOwnedTable]; !ok {
		t.Errorf("table %d missing from the sidecar-owned set, want it present", sidecarOwnedTable)
	}
	if _, ok := owned[hostOwnedTable]; ok {
		t.Errorf("table %d reported as sidecar-owned, want it left to the host", hostOwnedTable)
	}
}

// TestSidecarOwnedTableIDsOnAHostWithNoSidecar returns an empty set rather than
// an error, so a node running no ingress sidecar sweeps everything as before.
func TestSidecarOwnedTableIDsOnAHostWithNoSidecar(t *testing.T) {
	owned, err := SidecarOwnedTableIDs(vrfTableWith(t, map[uint32]uint64{hostOwnedTable: tenantLocatorBlock}))
	if err != nil {
		t.Fatalf("SidecarOwnedTableIDs = %v, want success", err)
	}
	if len(owned) != 0 {
		t.Errorf("sidecar-owned set = %v, want it empty", owned)
	}
}

// TestRefreshSkipsSidecarOwnedEntries is the regression test for #568: the host
// sweep rewrote entries the ingress sidecar had resolved inside a pod network
// namespace to a host interface index the pod does not have, dropping every
// encapsulated packet toward a VPC workload until the sidecar wrote them back.
func TestRefreshSkipsSidecarOwnedEntries(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	sid := net.ParseIP("2001:db8:ff02:9:e001::")
	if err := tbl.Register(sidecarOwnedTable, DefaultPrefix, sid); err != nil {
		t.Fatalf("Register(::/0) = %v, want success", err)
	}

	// The host namespace resolves this SID out a real fabric uplink. Writing
	// that index into an entry the pod forwards on is the defect.
	resolverFor(t, map[string]answer{
		sid.String(): {
			link: 1060,
			dmac: net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x07, 0x6E, 0x0B},
			smac: net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x46, 0x3D, 0x35},
		},
	})

	foreign, err := SidecarOwnedTableIDs(vrfTableWith(t, map[uint32]uint64{
		sidecarOwnedTable: uformat.BlockIngressSidecar,
	}))
	if err != nil {
		t.Fatalf("SidecarOwnedTableIDs = %v, want success", err)
	}

	result, err := tbl.Refresh(foreign)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Refreshed != 0 || result.Skipped != 1 {
		t.Errorf("Refresh() = %+v, want 0 refreshed and 1 skipped", result)
	}

	key, err := buildKey(sidecarOwnedTable, DefaultPrefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	value, err := lookupRaw(tbl, key)
	if err != nil {
		t.Fatalf("lookupRaw: %v", err)
	}
	if value.LinkIfindex != fakeLinkIndex {
		t.Errorf("link_ifindex = %d, want the sidecar's own %d left untouched", value.LinkIfindex, fakeLinkIndex)
	}
	if got := net.HardwareAddr(value.Smac[:]).String(); got != fakeSmac.String() {
		t.Errorf("smac = %s, want the sidecar's own %s left untouched", got, fakeSmac)
	}
}

// TestRefreshStillRewritesHostOwnedEntriesAlongsideSidecarOnes keeps #558's
// tenant-egress refresh working on a node that also runs an ingress sidecar:
// the host's own entry follows its next hop onto the new uplink while the
// sidecar's, resolving to the same host answer, is left alone.
func TestRefreshStillRewritesHostOwnedEntriesAlongsideSidecarOnes(t *testing.T) {
	stubResolveLinkAndL2(t)
	tbl := NewEgressRouteTable(newFakeTable())
	tenantSID := net.ParseIP("2001:db8:ff02:1:e001::")
	sidecarSID := net.ParseIP("2001:db8:ff02:9:e001::")

	// The tenant VRF's ::/0 toward an egress shard, written by a short-lived
	// CNI plugin before BGP converged a route to that shard.
	if err := tbl.Register(hostOwnedTable, DefaultPrefix, tenantSID); err != nil {
		t.Fatalf("Register(host ::/0) = %v, want success", err)
	}
	if err := tbl.Register(sidecarOwnedTable, DefaultPrefix, sidecarSID); err != nil {
		t.Fatalf("Register(sidecar ::/0) = %v, want success", err)
	}

	const uplinkIndex = 1060
	uplinkDmac := net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x07, 0x6E, 0x0B}
	uplinkSmac := net.HardwareAddr{0xAA, 0xC1, 0xAB, 0x46, 0x3D, 0x35}
	resolverFor(t, map[string]answer{
		tenantSID.String():  {link: uplinkIndex, dmac: uplinkDmac, smac: uplinkSmac},
		sidecarSID.String(): {link: uplinkIndex, dmac: uplinkDmac, smac: uplinkSmac},
	})

	foreign, err := SidecarOwnedTableIDs(vrfTableWith(t, map[uint32]uint64{
		hostOwnedTable:    tenantLocatorBlock,
		sidecarOwnedTable: uformat.BlockIngressSidecar,
	}))
	if err != nil {
		t.Fatalf("SidecarOwnedTableIDs = %v, want success", err)
	}

	result, err := tbl.Refresh(foreign)
	if err != nil {
		t.Fatalf("Refresh() = %v, want success", err)
	}
	if result.Refreshed != 1 || result.Skipped != 1 {
		t.Errorf("Refresh() = %+v, want 1 refreshed and 1 skipped", result)
	}

	hostKey, err := buildKey(hostOwnedTable, DefaultPrefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	hostValue, err := lookupRaw(tbl, hostKey)
	if err != nil {
		t.Fatalf("lookupRaw: %v", err)
	}
	if hostValue.LinkIfindex != uplinkIndex {
		t.Errorf("host entry link_ifindex = %d, want it moved to %d", hostValue.LinkIfindex, uplinkIndex)
	}

	sidecarKey, err := buildKey(sidecarOwnedTable, DefaultPrefix)
	if err != nil {
		t.Fatalf("buildKey: %v", err)
	}
	sidecarValue, err := lookupRaw(tbl, sidecarKey)
	if err != nil {
		t.Fatalf("lookupRaw: %v", err)
	}
	if sidecarValue.LinkIfindex != fakeLinkIndex {
		t.Errorf("sidecar entry link_ifindex = %d, want the original %d", sidecarValue.LinkIfindex, fakeLinkIndex)
	}
}
