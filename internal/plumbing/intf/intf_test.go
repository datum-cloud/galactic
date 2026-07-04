// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package intf_test

import (
	"testing"

	"go.datum.net/galactic/internal/plumbing/intf"
)

const (
	testVPCHex           = "0000000004d2" // 1234 decimal
	testVPCBase62        = "jU"           // 1234 decimal in base62
	testVPCAttachmentHex = "002a"         // 42 decimal
	testVPCAttachmentB62 = "G"            // 42 decimal in base62

	// Formatted for interface name generation (padded by the template).
	testVPC           = "0000000jU" // base62 of 1234, right-padded to 9 chars
	testVPCAttachment = "00G"       // base62 of 42, right-padded to 3 chars

	testMaxVPCAtt = "ffff"
)

func TestGenerateInterfaceNameVRF(t *testing.T) {
	expected := "G0000000jU00GV"
	got := intf.GenerateInterfaceNameVRF(testVPC, testVPCAttachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameVRF(%s, %s) = %s, want %s", testVPC, testVPCAttachment, got, expected)
	}
}

func TestGenerateInterfaceNameHost(t *testing.T) {
	expected := "G0000000jU00GH"
	got := intf.GenerateInterfaceNameHost(testVPC, testVPCAttachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameHost(%s, %s) = %s, want %s", testVPC, testVPCAttachment, got, expected)
	}
}

func TestGenerateInterfaceNameGuest(t *testing.T) {
	expected := "G0000000jU00GG"
	got := intf.GenerateInterfaceNameGuest(testVPC, testVPCAttachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameGuest(%s, %s) = %s, want %s", testVPC, testVPCAttachment, got, expected)
	}
}

func TestHexToBase62(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantError bool
	}{
		{"VPCValue", testVPCHex, testVPCBase62, false},
		{"VPCAttachmentValue", testVPCAttachmentHex, testVPCAttachmentB62, false},
		{"Zero", "0", "0", false},
		{"UppercaseInput", "4D2", testVPCBase62, false}, // input normalised to lowercase
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := intf.HexToBase62(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("HexToBase62(%s) error = %v, wantError = %v", tt.input, err, tt.wantError)
			}
			if !tt.wantError && got != tt.want {
				t.Errorf("HexToBase62(%s) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestBase62ToHex(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantError bool
	}{
		{"VPCValue", testVPCBase62, "4d2", false},
		{"VPCAttachmentValue", testVPCAttachmentB62, "2a", false},
		{"Zero", "0", "0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := intf.Base62ToHex(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("Base62ToHex(%s) error = %v, wantError = %v", tt.input, err, tt.wantError)
			}
			if !tt.wantError && got != tt.want {
				t.Errorf("Base62ToHex(%s) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestHexBase62RoundTrip(t *testing.T) {
	hexInputs := []string{"4d2", "2a", "0", "ffffffffffff", testMaxVPCAtt}
	for _, hex := range hexInputs {
		b62, err := intf.HexToBase62(hex)
		if err != nil {
			t.Errorf("HexToBase62(%s) unexpected error: %v", hex, err)
			continue
		}
		got, err := intf.Base62ToHex(b62)
		if err != nil {
			t.Errorf("Base62ToHex(%s) unexpected error: %v", b62, err)
			continue
		}
		if got != hex {
			t.Errorf("round-trip %s → %s → %s", hex, b62, got)
		}
	}
}
