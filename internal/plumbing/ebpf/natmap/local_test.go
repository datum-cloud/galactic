// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natmap

import (
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

func TestLocalTables_PutAllDelete(t *testing.T) {
	tables := LocalTables{Pair: newFakeTable(), Return: newFakeTable()}
	sid := netip.MustParseAddr("fc00:0:1:1:123::")
	natMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	tenMAC := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	if err := tables.Put(LocalPair{NATIfindex: 7, TenantSID: sid, NATMAC: natMAC, TenantMAC: tenMAC}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var rv natprog.NatNatLocalReturnValue
	if err := tables.Return.Lookup(natprog.NatNatLocalReturnKey{TenantSid: sid.As16()}, &rv); err != nil {
		t.Fatalf("return row: %v", err)
	}
	if rv.Ifindex != 7 || net.HardwareAddr(rv.Smac[:]).String() != natMAC.String() ||
		net.HardwareAddr(rv.Dmac[:]).String() != tenMAC.String() {
		t.Errorf("return row = %+v, want ifindex 7 framed %s -> %s", rv, natMAC, tenMAC)
	}

	all, err := tables.All()
	if err != nil || len(all) != 1 || all[0].NATIfindex != 7 || all[0].TenantSID != sid ||
		all[0].TenantMAC.String() != tenMAC.String() {
		t.Fatalf("All = %+v, %v", all, err)
	}

	if err := tables.DeletePair(7); err != nil {
		t.Fatalf("DeletePair: %v", err)
	}
	if err := tables.DeletePair(7); err != nil {
		t.Errorf("DeletePair of a missing row = %v, want nil", err)
	}
	if err := tables.DeleteReturn(sid); err != nil {
		t.Fatalf("DeleteReturn: %v", err)
	}
	if sids, _ := tables.ReturnSIDs(); len(sids) != 0 {
		t.Errorf("ReturnSIDs after delete = %v, want none", sids)
	}
}

func TestLocalTables_PutRefusesBadInput(t *testing.T) {
	tables := LocalTables{Pair: newFakeTable(), Return: newFakeTable()}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, p := range []LocalPair{
		{NATIfindex: 7, TenantSID: netip.MustParseAddr("10.0.0.1"), NATMAC: mac, TenantMAC: mac},
		{NATIfindex: 0, TenantSID: netip.MustParseAddr("fc00::1"), NATMAC: mac, TenantMAC: mac},
		{NATIfindex: 7, TenantSID: netip.MustParseAddr("fc00::1"), NATMAC: mac[:3], TenantMAC: mac},
	} {
		if err := tables.Put(p); err == nil {
			t.Errorf("Put(%+v) = nil, want an error", p)
		}
	}
}

func TestVLANTable_NetworkOrder(t *testing.T) {
	table := VLANTable{Table: newFakeTable()}
	e := VLANEgress{Ifindex: 9, LowerIfindex: 3, VID: 100, Proto: 0x8100}
	if err := table.Put(e); err != nil {
		t.Fatalf("Put: %v", err)
	}
	var raw natprog.NatNatVlanEgressValue
	if err := table.Table.Lookup(uint32(9), &raw); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	// The datapath copies these two fields onto the wire verbatim.
	if raw.Vid != 100<<8 || raw.Proto != 0x0081 {
		t.Errorf("stored vid %#x proto %#x, want network order (%#x, %#x)", raw.Vid, raw.Proto, 100<<8, 0x0081)
	}
	all, err := table.All()
	if err != nil || all[9] != e {
		t.Errorf("All = %+v, %v; want %+v", all, err, e)
	}
	if err := table.Put(VLANEgress{Ifindex: 9, VID: 4095}); err == nil {
		t.Error("Put of VLAN ID 4095 = nil, want an error")
	}
}
