// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6sid_test

import (
	"net"
	"testing"

	"go.datum.net/galactic/internal/operator/srv6sid"
	"go.datum.net/galactic/pkg/common/util"
)

func TestEncoderForAttachment(t *testing.T) {
	tests := []struct {
		name      string
		locator   string
		vpc       string
		attach    string
		wantSID   string
		wantError bool
	}{
		{
			name:    "MidValues56Locator",
			locator: "2607:ed40:ff00::/56",
			vpc:     "000004d2",
			attach:  "002a",
			wantSID: "2607:ed40:ff00:0:0:4d2:2a:0",
		},
		{
			name:    "MaxValues",
			locator: "fc00::/56",
			vpc:     "fffffffe",
			attach:  "fffe",
			wantSID: "fc00::ffff:fffe:fffe:0",
		},
		{
			name:      "BadLocator",
			locator:   "not-a-cidr",
			vpc:       "00000001",
			attach:    "0001",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := srv6sid.NewEncoder(tt.locator)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error from NewEncoder, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewEncoder error = %v", err)
			}
			got, err := enc.ForAttachment(tt.vpc, tt.attach)
			if err != nil {
				t.Fatalf("ForAttachment error = %v", err)
			}
			if !net.ParseIP(got).Equal(net.ParseIP(tt.wantSID)) {
				t.Errorf("ForAttachment(%s, %s) = %s, want %s", tt.vpc, tt.attach, got, tt.wantSID)
			}

			// Round-trip: decode the produced SID and confirm the
			// (vpc, attach) come back unchanged. Catches any drift in
			// the encoding layout.
			gotVPC, gotAttach, err := util.DecodeSRv6Endpoint(net.ParseIP(got))
			if err != nil {
				t.Fatalf("DecodeSRv6Endpoint error = %v", err)
			}
			if gotVPC != tt.vpc || gotAttach != tt.attach {
				t.Errorf("round-trip mismatch: encoded (%s,%s) -> %s -> (%s,%s)",
					tt.vpc, tt.attach, got, gotVPC, gotAttach)
			}
		})
	}
}
