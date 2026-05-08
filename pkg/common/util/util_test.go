// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package util_test

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"go.datum.net/galactic/pkg/common/util"
)

const (
	// Un-padded base62 form, as HexToBase62 actually returns it. The
	// InterfaceName template zero-pads to its declared widths (6 for VPC,
	// 3 for attachment).
	testVPC           = "jU" // 1234 dec, hex 000004d2 -> base62 jU
	testVPCAttachment = "G"  // 42 dec, hex 002a -> base62 G
)

func TestGenerateInterfaceNameVRF(t *testing.T) {
	expected := "G0000jU00GV"
	got := util.GenerateInterfaceNameVRF(testVPC, testVPCAttachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameVRF(%s, %s) = %s, want %s", testVPC, testVPCAttachment, got, expected)
	}
	if len(got) != 11 {
		t.Errorf("interface name %q length = %d, want 11 (1+6+3+1)", got, len(got))
	}
}

func TestGenerateInterfaceNameHost(t *testing.T) {
	expected := "G0000jU00GH"
	got := util.GenerateInterfaceNameHost(testVPC, testVPCAttachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameHost(%s, %s) = %s, want %s", testVPC, testVPCAttachment, got, expected)
	}
}

func TestGenerateInterfaceNameGuest(t *testing.T) {
	expected := "G0000jU00GG"
	got := util.GenerateInterfaceNameGuest(testVPC, testVPCAttachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameGuest(%s, %s) = %s, want %s", testVPC, testVPCAttachment, got, expected)
	}
}

// TestInterfaceNameMaxWidth is the regression guard for the kernel
// interface-name limit (IFNAMSIZ = 16 including NUL, so 15 chars max).
func TestInterfaceNameMaxWidth(t *testing.T) {
	// Worst case: maximum-width VPC and attachment ids.
	maxVPC := "ZZZZZZ" // 6 chars
	maxAttach := "ZZZ" // 3 chars
	for _, suffix := range []string{"V", "H", "G"} {
		got := fmt.Sprintf(util.InterfaceNameTemplate, maxVPC, maxAttach, suffix)
		if len(got) > 15 {
			t.Errorf("worst-case interface name %q length = %d, exceeds 15-char kernel limit", got, len(got))
		}
	}
}

func TestParseIP(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantIP    net.IP
		wantError bool
	}{
		{"ValidIPv4", "192.168.0.1", net.ParseIP("192.168.0.1"), false},
		{"ValidIPv6", "2607:ed40:ff00::1", net.ParseIP("2607:ed40:ff00::1"), false},
		{"InvalidIP", "not_an_ip", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.ParseIP(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseIP() error = %v, wantError = %v", err, tt.wantError)
			}
			if !reflect.DeepEqual(got, tt.wantIP) {
				t.Errorf("ParseIP() got = %v, want = %v", got, tt.wantIP)
			}
		})
	}
}

func TestParseSegments(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantIPs   []net.IP
		wantError bool
	}{
		{
			"ValidSingleSegment",
			[]string{"2607:ed40:ff00::1"},
			[]net.IP{net.ParseIP("2607:ed40:ff00::1")},
			false,
		},
		{
			"ValidMultipleSegments",
			[]string{"2607:ed40:ff00::1", "2607:ed40:ff01::1"},
			[]net.IP{net.ParseIP("2607:ed40:ff01::1"), net.ParseIP("2607:ed40:ff00::1")},
			false,
		},
		{
			"InvalidSegment",
			[]string{"2607:ed40:ff00::1", "invalid_ip"},
			nil,
			true,
		},
		{
			"InvalidIPv4Segment",
			[]string{"2607:ed40:ff00::1", "192.168.0.1"},
			nil,
			true,
		},
		{
			"EmptyInput",
			[]string{},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.ParseSegments(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseSegments() error = %v, wantError = %v", err, tt.wantError)
			}
			if !tt.wantError && !reflect.DeepEqual(got, tt.wantIPs) {
				t.Errorf("ParseSegments() got = %v, want = %v", got, tt.wantIPs)
			}
		})
	}
}

func TestDecodeSRv6Endpoint(t *testing.T) {
	// Layout in the lower 64 bits: <vpc-32>:<attach-16>:<zero-16>.
	// vpc=0x000004d2, attach=0x002a, with a 56-bit locator
	// 2607:ed40:ff00::/56:
	//   bytes 8..15 = 0x00 0x00 0x04 0xd2 0x00 0x2a 0x00 0x00
	srv6Endpoint := "2607:ed40:ff00:0:0:4d2:2a:0"
	wantVPC := "000004d2"
	wantAttach := "002a"
	gotVPC, gotAttach, err := util.DecodeSRv6Endpoint(net.ParseIP(srv6Endpoint))
	if err != nil {
		t.Fatalf("DecodeSRv6Endpoint(%s) error = %v", srv6Endpoint, err)
	}
	if gotVPC != wantVPC || gotAttach != wantAttach {
		t.Errorf("DecodeSRv6Endpoint(%s) = (%s, %s), want (%s, %s)",
			srv6Endpoint, gotVPC, gotAttach, wantVPC, wantAttach)
	}
}

func TestEncodeDecodeSRv6EndpointRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		locator   string
		vpc       string
		attach    string
		wantError bool
	}{
		{"Min", "fc00::/56", "00000001", "0001", false},
		{"Max", "fc00::/56", "fffffffe", "fffe", false},
		{"Mid", "2607:ed40:ff00::/56", "000004d2", "002a", false},
		{"VPCTooWide", "fc00::/56", "100000000", "0001", true}, // 33-bit VPC rejected
		{"AttachTooWide", "fc00::/56", "00000001", "10000", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid, err := util.EncodeSRv6Endpoint(tt.locator, tt.vpc, tt.attach)
			if (err != nil) != tt.wantError {
				t.Fatalf("Encode error = %v, wantError = %v", err, tt.wantError)
			}
			if tt.wantError {
				return
			}
			gotVPC, gotAttach, err := util.DecodeSRv6Endpoint(net.ParseIP(sid))
			if err != nil {
				t.Fatalf("Decode error = %v", err)
			}
			if gotVPC != tt.vpc || gotAttach != tt.attach {
				t.Errorf("round-trip mismatch: encoded %q -> sid %q -> (%q, %q)",
					fmt.Sprintf("%s/%s", tt.vpc, tt.attach), sid, gotVPC, gotAttach)
			}
		})
	}
}
