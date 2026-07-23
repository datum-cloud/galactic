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
