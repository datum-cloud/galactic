// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package intf_test

import (
	"net"
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
	hexInputs := []string{"4d2", "2a", "0", "ffffffffffff", "ffff"}
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

func TestEncodeSRv6Endpoint(t *testing.T) {
	tests := []struct {
		name          string
		srv6Net       string
		vpc           string
		vpcAttachment string
		want          string
		wantError     bool
	}{
		{
			name:          "Valid64BitMask",
			srv6Net:       "2607:ed40:ff00::/64",
			vpc:           testVPCHex,
			vpcAttachment: testVPCAttachmentHex,
			want:          "2607:ed40:ff00::4d2:2a",
		},
		{
			name:          "Valid48BitMask",
			srv6Net:       "2607:ed40:ff00::/48",
			vpc:           testVPCHex,
			vpcAttachment: testVPCAttachmentHex,
			want:          "2607:ed40:ff00::4d2:2a",
		},
		{
			name:          "ZeroIDs",
			srv6Net:       "2607:ed40:ff00::/64",
			vpc:           "000000000000",
			vpcAttachment: "0000",
			want:          "2607:ed40:ff00::",
		},
		{
			name:      "IPv4NetworkRejected",
			srv6Net:   "192.168.0.0/24",
			wantError: true,
		},
		{
			name:      "MaskTooNarrow",
			srv6Net:   "2607:ed40:ff00::/96",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := intf.EncodeSRv6Endpoint(tt.srv6Net, tt.vpc, tt.vpcAttachment)
			if (err != nil) != tt.wantError {
				t.Errorf("EncodeSRv6Endpoint() error = %v, wantError = %v", err, tt.wantError)
			}
			if !tt.wantError && got != tt.want {
				t.Errorf("EncodeSRv6Endpoint() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDecodeSRv6Endpoint(t *testing.T) {
	tests := []struct {
		name              string
		endpoint          string
		wantVPC           string
		wantVPCAttachment string
		wantError         bool
	}{
		{
			name:              "Valid",
			endpoint:          "2607:ed40:ff00::4d2:2a",
			wantVPC:           testVPCHex,
			wantVPCAttachment: testVPCAttachmentHex,
		},
		{
			name:              "ZeroIDs",
			endpoint:          "2607:ed40:ff00::",
			wantVPC:           "000000000000",
			wantVPCAttachment: "0000",
		},
		{
			name:              "MaxVPCAttachment",
			endpoint:          "2607:ed40:ff00::ffff",
			wantVPC:           "000000000000",
			wantVPCAttachment: "ffff",
		},
		{
			name:      "IPv4Rejected",
			endpoint:  "192.168.0.1",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVPC, gotAtt, err := intf.DecodeSRv6Endpoint(net.ParseIP(tt.endpoint))
			if (err != nil) != tt.wantError {
				t.Errorf("DecodeSRv6Endpoint() error = %v, wantError = %v", err, tt.wantError)
			}
			if !tt.wantError && (gotVPC != tt.wantVPC || gotAtt != tt.wantVPCAttachment) {
				t.Errorf("DecodeSRv6Endpoint(%s) = %s, %s, want %s, %s",
					tt.endpoint, gotVPC, gotAtt, tt.wantVPC, tt.wantVPCAttachment)
			}
		})
	}
}

func TestEncodeDecodeSRv6RoundTrip(t *testing.T) {
	locator := "2607:ed40:ff00::/64"
	cases := []struct{ vpc, att string }{
		{testVPCHex, testVPCAttachmentHex},
		{"000000000000", "0000"},
		{"ffffffffffff", "ffff"},
		{"000000000001", "0001"},
	}

	for _, c := range cases {
		encoded, err := intf.EncodeSRv6Endpoint(locator, c.vpc, c.att)
		if err != nil {
			t.Errorf("EncodeSRv6Endpoint(%s, %s) unexpected error: %v", c.vpc, c.att, err)
			continue
		}
		gotVPC, gotAtt, err := intf.DecodeSRv6Endpoint(net.ParseIP(encoded))
		if err != nil {
			t.Errorf("DecodeSRv6Endpoint(%s) unexpected error: %v", encoded, err)
			continue
		}
		if gotVPC != c.vpc || gotAtt != c.att {
			t.Errorf("round-trip vpc=%s att=%s → %s → vpc=%s att=%s", c.vpc, c.att, encoded, gotVPC, gotAtt)
		}
	}
}
