// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"testing"
)

const testUSID = "2001:db8:ff00:1010::1"

func TestParseSID(t *testing.T) {
	tests := []struct {
		name    string
		sid     string
		wantIP  string
		wantLen int
		wantErr bool
	}{
		{
			name:    "bare IPv6",
			sid:     testUSID,
			wantIP:  testUSID,
			wantLen: 128,
		},
		{
			name:    "CIDR /128",
			sid:     testUSID + "/128",
			wantIP:  testUSID,
			wantLen: 128,
		},
		{
			name:    "invalid IP",
			sid:     "not-an-ip",
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			sid:     testUSID + "/256",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSID(tt.sid)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSID(%q) error = nil, want error", tt.sid)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSID(%q) error = %v, want nil", tt.sid, err)
			}
			if got.IP.String() != tt.wantIP {
				t.Errorf("parseSID(%q).IP = %s, want %s", tt.sid, got.IP, tt.wantIP)
			}
			if _, bits := got.Mask.Size(); bits != tt.wantLen {
				t.Errorf("parseSID(%q).Mask.Size() = %d, want %d", tt.sid, bits, tt.wantLen)
			}
		})
	}
}

func Example_parseSID_bareIP() {
	// Bare IPv6 is wrapped in a /128 via netlink.NewIPNet.
	ipnet, err := parseSID("2001:db8::1")
	if err != nil {
		panic(err)
	}
	_, bits := ipnet.Mask.Size()
	_ = bits // 128
}
