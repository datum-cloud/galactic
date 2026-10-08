// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const testUSIDLocator = "2001:db8:ff01::/48"

func TestComputeSID(t *testing.T) {
	tests := []struct {
		name     string
		locator  string
		nodeID   int32
		argument int32
		function bgpv1alpha1.SRv6Function
		wantErr  bool
	}{
		{
			name:     "DT46 at /48 locator",
			locator:  testUSIDLocator,
			nodeID:   1,
			argument: 100,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
		},
		{
			name:     "max nodeID and argument",
			locator:  testUSIDLocator,
			nodeID:   uformat.NodeIDMax,
			argument: uformat.ArgumentMax,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
		},
		{
			name:     "min nodeID and argument",
			locator:  testUSIDLocator,
			nodeID:   uformat.NodeIDMin,
			argument: uformat.ArgumentMin,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
		},
		{
			name:     "not an IPv6 prefix",
			locator:  "203.0.113.0/24",
			nodeID:   1,
			argument: 1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "not a /48 -- too narrow",
			locator:  "2001:db8:ff01::/56",
			nodeID:   1,
			argument: 1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "not a /48 -- too wide",
			locator:  "2001:db8::/32",
			nodeID:   1,
			argument: 1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "nodeID 0 (below GIB range) reserved",
			locator:  testUSIDLocator,
			nodeID:   0,
			argument: 1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "nodeID above GIB range reserved",
			locator:  testUSIDLocator,
			nodeID:   uformat.NodeIDMax + 1,
			argument: 1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "argument 0 reserved",
			locator:  testUSIDLocator,
			nodeID:   1,
			argument: 0,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "argument out of range",
			locator:  testUSIDLocator,
			nodeID:   1,
			argument: uformat.ArgumentMax + 1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "unknown function",
			locator:  testUSIDLocator,
			nodeID:   1,
			argument: 1,
			function: bgpv1alpha1.SRv6Function("End.Bogus"),
			wantErr:  true,
		},
		{
			name:     "End.DT4 no longer supported",
			locator:  testUSIDLocator,
			nodeID:   1,
			argument: 1,
			function: bgpv1alpha1.SRv6Function("End.DT4"),
			wantErr:  true,
		},
		{
			name:     "End.DT6 no longer supported",
			locator:  testUSIDLocator,
			nodeID:   1,
			argument: 1,
			function: bgpv1alpha1.SRv6Function("End.DT6"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComputeSID(tt.locator, tt.nodeID, tt.argument, tt.function)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ComputeSID() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ComputeSID() unexpected error: %v", err)
			}

			// Cross-check against uformat's independently-tested encoder
			// rather than a hand-transcribed literal, so this test verifies
			// ComputeSID's locator-parsing/validation wrapper agrees with
			// the field layout uformat already exercises directly.
			prefix, err := netip.ParsePrefix(tt.locator)
			if err != nil {
				t.Fatalf("parse locator %q: %v", tt.locator, err)
			}
			block, err := uformat.Block(prefix.Addr())
			if err != nil {
				t.Fatalf("uformat.Block() error: %v", err)
			}
			want, err := uformat.Encode(uformat.Fields{
				Block:    block,
				NodeID:   uint16(tt.nodeID),
				Function: uformat.FunctionEndDT46,
				Argument: uint16(tt.argument),
			})
			if err != nil {
				t.Fatalf("uformat.Encode() error: %v", err)
			}
			if got != want {
				t.Errorf("ComputeSID() = %s, want %s", got, want)
			}

			// Decode confirms every field round-trips at its documented
			// fixed offset -- catching an offset/shift regression that a
			// same-package cross-check against Encode alone would not.
			fields, err := uformat.Decode(got)
			if err != nil {
				t.Fatalf("uformat.Decode() error: %v", err)
			}
			if fields.NodeID != uint16(tt.nodeID) {
				t.Errorf("decoded NodeID = %#x, want %#x", fields.NodeID, uint16(tt.nodeID))
			}
			if fields.Argument != uint16(tt.argument) {
				t.Errorf("decoded Argument = %#x, want %#x", fields.Argument, uint16(tt.argument))
			}
			if fields.Function != uformat.FunctionEndDT46 {
				t.Errorf("decoded Function = %#x, want %#x", fields.Function, uint8(uformat.FunctionEndDT46))
			}
		})
	}
}

func TestComputeSIDDeterministic(t *testing.T) {
	a, err := ComputeSID(testUSIDLocator, 7, 42, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatalf("ComputeSID() error: %v", err)
	}
	b, err := ComputeSID(testUSIDLocator, 7, 42, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatalf("ComputeSID() error: %v", err)
	}
	if a != b {
		t.Errorf("ComputeSID() not deterministic: %s != %s", a, b)
	}
}

// TestNodeSIDBaseMatchesComputeSIDWithArgumentSpliced is the contract usid.c's
// encapsulation source rests on: the base this returns, plus the Argument the
// datapath splices into bits 69-80, must reproduce byte for byte the SID
// ComputeSID hands the same attachment's BGPAdvertisement. A shard's reply is
// addressed to whatever the datapath stamped, so a divergence here sends every
// masqueraded flow's reply to an address no node decapsulates (#550).
func TestNodeSIDBaseMatchesComputeSIDWithArgumentSpliced(t *testing.T) {
	const nodeID = 9

	for _, argument := range []int32{
		uformat.ArgumentMin,
		0x123, // both nibbles of the split byte in play
		0x0FF, // carries only in the low byte
		uformat.ArgumentMax,
	} {
		base, err := NodeSIDBase(testUSIDLocator, nodeID)
		if err != nil {
			t.Fatalf("NodeSIDBase() error: %v", err)
		}

		// The same two byte writes usid_egress performs, in the same order.
		spliced := base.As16()
		spliced[8] = (spliced[8] & 0xF0) | byte(uint16(argument)>>8)&0x0F
		spliced[9] = byte(uint16(argument))

		want, err := ComputeSID(testUSIDLocator, nodeID, argument, bgpv1alpha1.SRv6FunctionEndDT46)
		if err != nil {
			t.Fatalf("ComputeSID() error: %v", err)
		}
		if got := netip.AddrFrom16(spliced); got != want {
			t.Errorf("NodeSIDBase()+argument %#x = %s, want %s", argument, got, want)
		}
	}
}

// TestNodeSIDBaseLeavesArgumentZero pins the one field the datapath owns. A
// base carrying a non-zero Argument would name some arbitrary tenant's VRF
// wherever the splice did not overwrite it; zero is the reserved value
// vrf_table must always miss, so a base that reached the wire unchanged is
// dropped rather than delivered to the wrong tenant.
func TestNodeSIDBaseLeavesArgumentZero(t *testing.T) {
	base, err := NodeSIDBase(testUSIDLocator, 9)
	if err != nil {
		t.Fatalf("NodeSIDBase() error: %v", err)
	}
	fields, err := uformat.Decode(base)
	if err != nil {
		t.Fatalf("uformat.Decode() error: %v", err)
	}
	if fields.Argument != 0 {
		t.Errorf("decoded Argument = %#x, want 0", fields.Argument)
	}
	if fields.NodeID != 9 {
		t.Errorf("decoded NodeID = %#x, want 9", fields.NodeID)
	}
	if fields.Function != uformat.FunctionEndDT46 {
		t.Errorf("decoded Function = %#x, want %#x", fields.Function, uint8(uformat.FunctionEndDT46))
	}
}

// TestNodeSIDBaseRejectsUnusableIdentity covers the inputs that must fail
// loudly rather than produce a plausible-looking address: without a valid
// locator and node ID there is no SID, and node_src_addr_table's "all-zero
// means not configured" convention would read a zero-value result as a
// legitimate one.
func TestNodeSIDBaseRejectsUnusableIdentity(t *testing.T) {
	tests := []struct {
		name    string
		locator string
		nodeID  int32
	}{
		{"empty locator", "", 9},
		{"not a prefix", "2001:db8:ff01::", 9},
		{"IPv4 locator", "10.0.0.0/8", 9},
		{"wrong prefix length", "2001:db8:ff01::/64", 9},
		{"node ID below range", testUSIDLocator, uformat.NodeIDMin - 1},
		{"node ID above range", testUSIDLocator, uformat.NodeIDMax + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NodeSIDBase(tt.locator, tt.nodeID); err == nil {
				t.Errorf("NodeSIDBase(%q, %d) = nil error, want an error", tt.locator, tt.nodeID)
			}
		})
	}
}

// TestNodeLocatorAddress pins galactic-gateway's derived encapsulation source
// to the values deployments set by hand before #707: the node's Block and
// Node-ID, with nothing after them. The lab rows are its four edge nodes.
func TestNodeLocatorAddress(t *testing.T) {
	tests := []struct {
		name    string
		locator string
		nodeID  int32
		want    string
		wantErr bool
	}{
		{name: "dfw-worker2", locator: "2001:db8:ff01::/48", nodeID: 0x1002, want: "2001:db8:ff01:1002::"},
		{name: "dfw-worker3", locator: "2001:db8:ff01::/48", nodeID: 0x1003, want: "2001:db8:ff01:1003::"},
		{name: "sjc-worker2", locator: "2001:db8:ff02::/48", nodeID: 0x1002, want: "2001:db8:ff02:1002::"},
		{name: "iad-worker2", locator: "2001:db8:ff03::/48", nodeID: 0x1002, want: "2001:db8:ff03:1002::"},
		{name: "locator not a /48", locator: "2001:db8:ff01::/64", nodeID: 0x1002, wantErr: true},
		{name: "IPv4 locator", locator: "10.0.0.0/8", nodeID: 0x1002, wantErr: true},
		{name: "unparseable locator", locator: "not-a-prefix", nodeID: 0x1002, wantErr: true},
		{name: "node ID zero", locator: testUSIDLocator, nodeID: 0, wantErr: true},
		{name: "node ID in reserved range", locator: testUSIDLocator, nodeID: 0xE000, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NodeLocatorAddress(tc.locator, tc.nodeID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NodeLocatorAddress() = %s, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NodeLocatorAddress() error: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("NodeLocatorAddress() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestNodeLocatorAddressNamesSameNodeAsSIDBase checks that the gateway's
// source and the CNI's SID base cannot drift apart: they share bits 1-64.
func TestNodeLocatorAddressNamesSameNodeAsSIDBase(t *testing.T) {
	addr, err := NodeLocatorAddress(testUSIDLocator, 9)
	if err != nil {
		t.Fatalf("NodeLocatorAddress() error: %v", err)
	}
	base, err := NodeSIDBase(testUSIDLocator, 9)
	if err != nil {
		t.Fatalf("NodeSIDBase() error: %v", err)
	}
	a, b := addr.As16(), base.As16()
	if [8]byte(a[:8]) != [8]byte(b[:8]) {
		t.Errorf("NodeLocatorAddress() %s and NodeSIDBase() %s differ in bits 1-64", addr, base)
	}
}

// TestBackendSlot checks BackendSlot is deterministic, never zero, and tells
// apart a handful of backends sharing a node, including two that differ only by
// port.
func TestBackendSlot(t *testing.T) {
	backends := []netip.AddrPort{
		netip.MustParseAddrPort("[fd20:60:ff03:a::100]:80"),
		netip.MustParseAddrPort("[fd20:60:ff03:a::101]:80"),
		netip.MustParseAddrPort("[fd20:60:ff03:a::102]:80"),
		netip.MustParseAddrPort("[fd20:60:ff03:a::100]:8080"),
		netip.MustParseAddrPort("[fd00:10:1::1]:8443"),
	}
	seen := make(map[uint16]netip.AddrPort, len(backends))
	for _, b := range backends {
		slot := BackendSlot(b.Addr(), b.Port())
		if slot == 0 {
			t.Errorf("BackendSlot(%s) = 0, want nonzero", b)
		}
		if again := BackendSlot(b.Addr(), b.Port()); again != slot {
			t.Errorf("BackendSlot(%s) not deterministic: %#x then %#x", b, slot, again)
		}
		if prev, dup := seen[slot]; dup {
			t.Errorf("BackendSlot(%s) = %#x, same as %s", b, slot, prev)
		}
		seen[slot] = b
	}
}

// TestComputeBackendSID checks the slot lands in the SID's Slot field, leaves
// every other field equal to ComputeSID's, and that slot zero is ComputeSID.
func TestComputeBackendSID(t *testing.T) {
	plain, err := ComputeSID(testUSIDLocator, 7, 0x123, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatalf("ComputeSID: %v", err)
	}
	zero, err := ComputeBackendSID(testUSIDLocator, 7, 0x123, bgpv1alpha1.SRv6FunctionEndDT46, 0)
	if err != nil {
		t.Fatalf("ComputeBackendSID(slot 0): %v", err)
	}
	if zero != plain {
		t.Errorf("ComputeBackendSID(slot 0) = %s, want ComputeSID's %s", zero, plain)
	}

	slot := BackendSlot(netip.MustParseAddr("fd20:60:ff03:a::100"), 80)
	sid, err := ComputeBackendSID(testUSIDLocator, 7, 0x123, bgpv1alpha1.SRv6FunctionEndDT46, slot)
	if err != nil {
		t.Fatalf("ComputeBackendSID: %v", err)
	}
	got, err := uformat.Decode(sid)
	if err != nil {
		t.Fatalf("uformat.Decode(%s): %v", sid, err)
	}
	want, err := uformat.Decode(plain)
	if err != nil {
		t.Fatalf("uformat.Decode(%s): %v", plain, err)
	}
	want.Slot = slot
	if got != want {
		t.Errorf("Decode(ComputeBackendSID) = %+v, want %+v", got, want)
	}
}
