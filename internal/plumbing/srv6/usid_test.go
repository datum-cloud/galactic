// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"testing"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const testUSIDLocator = "2001:db8:ff01::/48"

func TestComputeSID(t *testing.T) {
	tests := []struct {
		name     string
		locator  string
		nodeID   int32
		vrfID    int32
		function bgpv1alpha1.SRv6Function
		want     string
		wantErr  bool
	}{
		{
			name:     "DT46 at /48 locator",
			locator:  testUSIDLocator,
			nodeID:   1,
			vrfID:    100,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			want:     "2001:db8:ff01:100:6400::",
		},
		{
			name:     "DT4 uses distinct function byte from DT46",
			locator:  testUSIDLocator,
			nodeID:   1,
			vrfID:    100,
			function: bgpv1alpha1.SRv6FunctionEndDT4,
			want:     "2001:db8:ff01:100:6404::",
		},
		{
			name:     "DT6 uses distinct function byte from DT4/DT46",
			locator:  testUSIDLocator,
			nodeID:   1,
			vrfID:    100,
			function: bgpv1alpha1.SRv6FunctionEndDT6,
			want:     "2001:db8:ff01:100:6406::",
		},
		{
			name:     "max nodeID and vrfID",
			locator:  testUSIDLocator,
			nodeID:   254,
			vrfID:    65535,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			want:     "2001:db8:ff01:feff:ff00::",
		},
		{
			name:     "not an IPv6 prefix",
			locator:  "203.0.113.0/24",
			nodeID:   1,
			vrfID:    1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "unaligned prefix length",
			locator:  "2001:db8:ff01::/49",
			nodeID:   1,
			vrfID:    1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "no room for suffix",
			locator:  "2001:db8:ff01::/104",
			nodeID:   1,
			vrfID:    1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "nodeID 0 reserved",
			locator:  testUSIDLocator,
			nodeID:   0,
			vrfID:    1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "nodeID 255 reserved",
			locator:  testUSIDLocator,
			nodeID:   255,
			vrfID:    1,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "vrfID 0 reserved",
			locator:  testUSIDLocator,
			nodeID:   1,
			vrfID:    0,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "vrfID out of range",
			locator:  testUSIDLocator,
			nodeID:   1,
			vrfID:    65536,
			function: bgpv1alpha1.SRv6FunctionEndDT46,
			wantErr:  true,
		},
		{
			name:     "unknown function",
			locator:  testUSIDLocator,
			nodeID:   1,
			vrfID:    1,
			function: bgpv1alpha1.SRv6Function("End.Bogus"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComputeSID(tt.locator, tt.nodeID, tt.vrfID, tt.function)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ComputeSID() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ComputeSID() unexpected error: %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("ComputeSID() = %s, want %s", got.String(), tt.want)
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
