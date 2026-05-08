// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package identifier_test

import (
	"testing"

	"go.datum.net/galactic/internal/operator/identifier"
)

func TestForVPC(t *testing.T) {
	id := identifier.NewFromSeed(424242)
	tests := []struct {
		name           string
		value          uint64
		wantIdentifier string
		wantError      bool
	}{
		{"InvalidSpecialMin", 0, "", true},
		{"InvalidSpecialMax", 0xFFFFFFFF, "", true},
		{"ValidMin", 1, "00000001", false},
		{"ValidMax", 0xFFFFFFFF - 1, "fffffffe", false},
		{"Valid", 12345, "00003039", false},
		{"InvalidMax", 0xFFFFFFFF + 1, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := id.FromValue(tt.value, identifier.MaxVPC)
			if (err != nil) != tt.wantError {
				t.Errorf("NewFromInteger() error = %v, wantError = %v", err, tt.wantError)
			}
			if got != tt.wantIdentifier {
				t.Errorf("NewFromInteger() got = %v, want = %v", got, tt.wantIdentifier)
			}
		})
	}
}

// TestForVPCWidth is the regression guard for the 32-bit VPC ID width
// decision. If a future change widens or narrows the VPC ID, this test
// fires loudly rather than silently breaking BGP RD/RT formatting and
// the SRv6 SID layout.
func TestForVPCWidth(t *testing.T) {
	id := identifier.NewFromSeed(1)
	got, err := id.ForVPC()
	if err != nil {
		t.Fatalf("ForVPC() error = %v", err)
	}
	if len(got) != 8 {
		t.Errorf("ForVPC() returned %q (len %d), want 8-char hex", got, len(got))
	}
}

func TestForVPCAttachment(t *testing.T) {
	id := identifier.NewFromSeed(424242)
	tests := []struct {
		name           string
		value          uint64
		wantIdentifier string
		wantError      bool
	}{
		{"InvalidSpecialMin", 0, "", true},
		{"InvalidSpecialMax", 0xFFFF, "", true},
		{"ValidMin", 1, "0001", false},
		{"ValidMax", 0xFFFF - 1, "fffe", false},
		{"Valid", 12345, "3039", false},
		{"InvalidMax", 0xFFFF + 1, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := id.FromValue(tt.value, identifier.MaxVPCAttachment)
			if (err != nil) != tt.wantError {
				t.Errorf("NewFromInteger() error = %v, wantError = %v", err, tt.wantError)
			}
			if got != tt.wantIdentifier {
				t.Errorf("NewFromInteger() got = %v, want = %v", got, tt.wantIdentifier)
			}
		})
	}
}
