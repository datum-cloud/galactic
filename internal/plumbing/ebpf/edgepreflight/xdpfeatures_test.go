// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgepreflight

import (
	"testing"

	"github.com/mdlayher/netlink"
)

// encodeFeatures builds the attribute payload a netdev reply carries, so the
// decoder is exercised against the same wire shape the kernel produces.
func encodeFeatures(t *testing.T, attrType uint16, value uint64) []byte {
	t.Helper()
	enc := netlink.NewAttributeEncoder()
	enc.Uint32(netdevAttrDevIfindex, 3)
	enc.Uint64(attrType, value)
	data, err := enc.Encode()
	if err != nil {
		t.Fatalf("encode netdev reply: %v", err)
	}
	return data
}

func TestXDPFeaturesFrom(t *testing.T) {
	tests := map[string]struct {
		data         []byte
		wantFeatures uint64
		wantFound    bool
	}{
		"driver reports the basic actions": {
			data:         encodeFeatures(t, netdevAttrDevXDPFeatures, netdevXDPActBasic|2|4),
			wantFeatures: netdevXDPActBasic | 2 | 4,
			wantFound:    true,
		},
		// A driver with no ndo_bpf at all is reported with an empty
		// feature set rather than by omitting the attribute.
		"driver reports no actions": {
			data:         encodeFeatures(t, netdevAttrDevXDPFeatures, 0),
			wantFeatures: 0,
			wantFound:    true,
		},
		"reply carries no feature attribute": {
			data:      encodeFeatures(t, netdevAttrDevXDPZCMaxSegs, 1),
			wantFound: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			features, found, err := xdpFeaturesFrom(tc.data)
			if err != nil {
				t.Fatalf("xdpFeaturesFrom: %v", err)
			}
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if features != tc.wantFeatures {
				t.Errorf("features = %#x, want %#x", features, tc.wantFeatures)
			}
			if tc.wantFound && (features&netdevXDPActBasic != 0) != (tc.wantFeatures&netdevXDPActBasic != 0) {
				t.Error("basic-action bit did not survive the round trip")
			}
		})
	}
}
