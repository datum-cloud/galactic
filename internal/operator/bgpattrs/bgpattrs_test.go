// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bgpattrs_test

import (
	"testing"

	"go.datum.net/galactic/internal/operator/bgpattrs"
)

func TestFormatter(t *testing.T) {
	tests := []struct {
		name      string
		asn       uint32
		vpc       string
		wantRD    string
		wantRT    string
		wantError bool
	}{
		{"Min", 65000, "00000001", "65000:1", "65000:1", false},
		{"Mid", 65000, "000004d2", "65000:1234", "65000:1234", false},
		{"Max", 4200000000, "fffffffe", "4200000000:4294967294", "4200000000:4294967294", false},
		{"InvalidHex", 65000, "zz", "", "", true},
		{"TooWide", 65000, "100000000", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := bgpattrs.NewFormatter(tt.asn)
			if err != nil {
				t.Fatalf("NewFormatter error = %v", err)
			}
			gotRD, errRD := f.RD(tt.vpc)
			gotRT, errRT := f.RT(tt.vpc)
			if tt.wantError {
				if errRD == nil || errRT == nil {
					t.Fatalf("expected errors, got rd=%v rt=%v", errRD, errRT)
				}
				return
			}
			if errRD != nil || errRT != nil {
				t.Fatalf("unexpected errors: rd=%v rt=%v", errRD, errRT)
			}
			if gotRD != tt.wantRD {
				t.Errorf("RD = %q, want %q", gotRD, tt.wantRD)
			}
			if gotRT != tt.wantRT {
				t.Errorf("RT = %q, want %q", gotRT, tt.wantRT)
			}
		})
	}
}

func TestNewFormatterRejectsZeroASN(t *testing.T) {
	if _, err := bgpattrs.NewFormatter(0); err == nil {
		t.Fatal("expected error for asn=0")
	}
}
