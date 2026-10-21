// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"fmt"
	"net/netip"
	"testing"
)

// TestFlowHash_KnownValues pins FlowHash to fixed outputs, so a change to the
// hash on either side fails without root. TestEdgeLB_PicksTheSlotFlowHashPredicts
// ties these values to the loaded program, and they were also checked against
// an independent implementation of FNV-1a and fmix32.
func TestFlowHash_KnownValues(t *testing.T) {
	tests := []struct {
		addr string
		port uint16
		want uint32
	}{
		{"::", 0, 0x3c2b6e16},
		{"2001:db8:ffff::1", 40000, 0xf88dae54},
		{"2001:db8:ffff::1", 40001, 0xca4d8f14},
		{"::ffff:198.51.100.7", 40000, 0x5e88eb3a},
		{"::ffff:198.51.100.7", 65535, 0x4711f2c7},
	}
	for _, tt := range tests {
		if got := FlowHash(netip.MustParseAddr(tt.addr).As16(), tt.port); got != tt.want {
			t.Errorf("FlowHash(%s, %d) = %#08x, want %#08x", tt.addr, tt.port, got, tt.want)
		}
	}
}

// TestEdgeLB_PicksTheSlotFlowHashPredicts checks FlowHash against the loaded
// program. The VIP holds the most backends a rule can, and slot i of its table
// names backend i mod that count, so the backend edge_lb encapsulates toward
// gives away the slot it picked modulo that count. Every flow must match
// FlowHash's prediction, for an IPv6 and an IPv4 client over 64 consecutive
// source ports.
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
	putIPv4VIP(t, objs, ipprotoTCP, 443, vip6, usids...)
	putIPv4VIP(t, objs, ipprotoTCP, 443, testVIP4, usids...)

	tests := []struct {
		name   string
		vip    netip.Addr
		client netip.Addr
	}{
		{"IPv6 client", vip6, netip.MustParseAddr("2001:db8:ffff::1")},
		{"IPv4 client", testVIP4, testClient4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for sport := uint16(40000); sport < 40064; sport++ {
				var pkt []byte
				if tt.client.Is4() {
					pkt = buildIPv4Packet(t, ipprotoTCP, tt.vip, tt.client, sport, 443, nil, ip4Opts{})
				} else {
					pkt = buildL4Packet(t, ipprotoTCP, tt.vip, tt.client, sport, 443, nil)
				}
				_, out := runLB(t, objs, pkt)
				if len(out) < ethLen+40 {
					t.Fatalf("source port %d: output %d bytes, want an outer header", sport, len(out))
				}

				// An IPv4 client is hashed in its IPv4-mapped form, as As16 gives it.
				slot := FlowHash(tt.client.As16(), sport) % tableSize
				want := usids[slot%maxBackends]
				if got := addrAt(out[ethLen:], 24); got != want {
					t.Errorf("source port %d: encapsulated toward %v, want %v (slot %d)", sport, got, want, slot)
				}
			}
		})
	}
}
