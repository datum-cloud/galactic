// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"fmt"
	"net/netip"
	"testing"
)

// TestFlowHash_KnownValues pins FlowHash to fixed outputs for each affinity,
// so a change to the hash on either side fails without root.
// TestEdgeLB_PicksTheSlotFlowHashPredicts ties these values to the loaded
// program, and they were also checked against an independent implementation of
// FNV-1a and fmix32. Under AffinityClientIP the protocol and port change
// nothing, and under AffinityClientIPAndProtocol the port changes nothing.
func TestFlowHash_KnownValues(t *testing.T) {
	const (
		client6 = "2001:db8:ffff::1"
		client4 = "::ffff:198.51.100.7"
	)
	tests := []struct {
		addr     string
		affinity uint8
		proto    uint8
		port     uint16
		want     uint32
	}{
		{"::", AffinityNone, 0, 0, 0x3c2b6e16},
		{client6, AffinityNone, ipprotoTCP, 40000, 0xf88dae54},
		{client6, AffinityNone, ipprotoUDP, 40000, 0xf88dae54},
		{client6, AffinityNone, ipprotoTCP, 40001, 0xca4d8f14},
		{client4, AffinityNone, ipprotoTCP, 40000, 0x5e88eb3a},
		{client4, AffinityNone, ipprotoTCP, 65535, 0x4711f2c7},
		{client6, AffinityClientIP, ipprotoTCP, 40000, 0x546a4eb1},
		{client6, AffinityClientIP, ipprotoUDP, 1, 0x546a4eb1},
		{client4, AffinityClientIP, ipprotoTCP, 40000, 0xd6aa8729},
		{client6, AffinityClientIPAndProtocol, ipprotoTCP, 40000, 0xf4e8b80c},
		{client6, AffinityClientIPAndProtocol, ipprotoTCP, 1, 0xf4e8b80c},
		{client6, AffinityClientIPAndProtocol, ipprotoUDP, 40000, 0x440e8af6},
		{client4, AffinityClientIPAndProtocol, ipprotoTCP, 1, 0xc5c414dc},
		// An affinity the datapath does not know hashes as AffinityNone.
		{client6, 7, ipprotoTCP, 40000, 0xf88dae54},
	}
	for _, tt := range tests {
		got := FlowHash(netip.MustParseAddr(tt.addr).As16(), tt.affinity, tt.proto, tt.port)
		if got != tt.want {
			t.Errorf("FlowHash(%s, affinity %d, proto %d, port %d) = %#08x, want %#08x",
				tt.addr, tt.affinity, tt.proto, tt.port, got, tt.want)
		}
	}
}

// TestEdgeLB_PicksTheSlotFlowHashPredicts checks FlowHash against the loaded
// program. The VIP holds the most backends a rule can, and slot i of its table
// names backend i mod that count, so the backend edge_lb encapsulates toward
// gives away the slot it picked modulo that count. Every flow must match
// FlowHash's prediction under each affinity, for an IPv6 and an IPv4 client
// over TCP and UDP and 64 consecutive source ports.
func TestEdgeLB_PicksTheSlotFlowHashPredicts(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	// Both sizes come from the C definitions, through the generated type.
	var value EdgedsrVipValue
	maxBackends, tableSize := uint32(len(value.Backends)), uint32(len(value.MaglevTable))

	usids := make([]netip.Addr, maxBackends)
	for i := range usids {
		usids[i] = netip.MustParseAddr(fmt.Sprintf("fc00:1:%x::1", i+1))
	}
	vip6 := netip.MustParseAddr("2001:db8::100")
	keys := []EdgedsrVipKey{
		putIPv4VIP(t, objs, ipprotoTCP, 443, vip6, usids...),
		putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, usids...),
		putIPv4VIP(t, objs, ipprotoUDP, 443, vip6, usids...),
		putIPv4VIP(t, objs, ipprotoUDP, 443, testVIP4, usids...),
	}

	tests := []struct {
		name   string
		proto  uint8
		vip    netip.Addr
		client netip.Addr
	}{
		{"IPv6 TCP client", ipprotoTCP, vip6, netip.MustParseAddr("2001:db8:ffff::1")},
		{"IPv4 TCP client", ipprotoTCP, testVIP4, testClient4},
		{"IPv6 UDP client", ipprotoUDP, vip6, netip.MustParseAddr("2001:db8:ffff::1")},
		{"IPv4 UDP client", ipprotoUDP, testVIP4, testClient4},
	}
	for _, affinity := range []uint8{AffinityNone, AffinityClientIP, AffinityClientIPAndProtocol} {
		for _, key := range keys {
			var value EdgedsrVipValue
			if err := objs.VipTable.Lookup(key, &value); err != nil {
				t.Fatalf("read vip_table: %v", err)
			}
			value.Affinity = affinity
			if err := objs.VipTable.Put(key, value); err != nil {
				t.Fatalf("set affinity %d: %v", affinity, err)
			}
		}
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s/affinity %d", tt.name, affinity), func(t *testing.T) {
				for sport := uint16(40000); sport < 40064; sport++ {
					var pkt []byte
					if tt.client.Is4() {
						pkt = buildIPv4Packet(t, tt.proto, tt.vip, tt.client, sport, 443, nil, ip4Opts{})
					} else {
						pkt = buildL4Packet(t, tt.proto, tt.vip, tt.client, sport, 443, nil)
					}
					_, out := runLB(t, objs, pkt)
					if len(out) < ethLen+40 {
						t.Fatalf("source port %d: output %d bytes, want an outer header", sport, len(out))
					}

					// An IPv4 client is hashed in its IPv4-mapped form, as As16 gives it.
					slot := FlowHash(tt.client.As16(), affinity, tt.proto, sport) % tableSize
					want := usids[slot%maxBackends]
					if got := addrAt(out[ethLen:], 24); got != want {
						t.Errorf("source port %d: encapsulated toward %v, want %v (slot %d)", sport, got, want, slot)
					}
				}
			})
		}
	}
}
