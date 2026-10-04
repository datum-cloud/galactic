// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"net/netip"
	"testing"
)

var (
	testGW6 = netip.MustParseAddr("fd20:70::1")
	testGW4 = netip.MustParseAddr("172.21.1.1")
)

func TestGatewayTable_RegisterAndGet(t *testing.T) {
	for _, tt := range []struct {
		name     string
		gw6, gw4 netip.Addr
	}{
		{name: "dual stack", gw6: testGW6, gw4: testGW4},
		{name: "IPv6 only", gw6: testGW6},
		{name: "IPv4 only", gw4: testGW4},
		{name: "IPv4-mapped IPv4 gateway", gw4: netip.AddrFrom16(testGW4.As16())},
	} {
		t.Run(tt.name, func(t *testing.T) {
			table := NewGatewayTable(newFakeTable())
			if err := table.Register(vethIfindex, tt.gw6, tt.gw4); err != nil {
				t.Fatalf("Register: %v", err)
			}
			gw6, gw4, ok, err := table.Get(vethIfindex)
			if err != nil || !ok {
				t.Fatalf("Get = ok %v, err %v; want the entry", ok, err)
			}
			if gw6 != tt.gw6 {
				t.Errorf("IPv6 gateway = %v, want %v", gw6, tt.gw6)
			}
			if want := tt.gw4.Unmap(); gw4 != want {
				t.Errorf("IPv4 gateway = %v, want %v", gw4, want)
			}
		})
	}
}

// A gateway in the wrong family would make the datapath send errors from an
// address the tenant cannot use, so it is rejected rather than written.
func TestGatewayTable_RejectsWrongFamily(t *testing.T) {
	table := NewGatewayTable(newFakeTable())
	if err := table.Register(vethIfindex, testGW4, netip.Addr{}); err == nil {
		t.Error("Register with an IPv4 address as the IPv6 gateway = nil, want an error")
	}
	if err := table.Register(vethIfindex, netip.AddrFrom16(testGW4.As16()), netip.Addr{}); err == nil {
		t.Error("Register with an IPv4-mapped address as the IPv6 gateway = nil, want an error")
	}
	if err := table.Register(vethIfindex, netip.Addr{}, testGW6); err == nil {
		t.Error("Register with an IPv6 address as the IPv4 gateway = nil, want an error")
	}
	if _, _, ok, _ := table.Get(vethIfindex); ok {
		t.Error("a rejected Register left an entry behind")
	}
}

func TestGatewayTable_UnregisterIsIdempotent(t *testing.T) {
	table := NewGatewayTable(newFakeTable())
	if err := table.Register(vethIfindex, testGW6, testGW4); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for i := range 2 {
		if err := table.Unregister(vethIfindex); err != nil {
			t.Fatalf("Unregister #%d: %v", i+1, err)
		}
	}
	if _, _, ok, err := table.Get(vethIfindex); ok || err != nil {
		t.Errorf("Get after Unregister = ok %v, err %v; want no entry", ok, err)
	}
}
