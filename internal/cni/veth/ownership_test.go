// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package veth

import (
	"testing"

	"github.com/vishvananda/netlink"
)

// testOwnerA and testOwnerB stand for two CNI container IDs contending for the
// same attachment.
const (
	testOwnerA = "container-a"
	testOwnerB = "container-b"
)

func linkWithAlias(alias string) netlink.Link {
	return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "G000000010010H", Alias: alias}}
}

func TestOwnedBy(t *testing.T) {
	tests := []struct {
		name    string
		alias   string
		ownerID string
		want    bool
	}{
		{
			name:    "the container that created it still owns it",
			alias:   testOwnerA,
			ownerID: testOwnerA,
			want:    true,
		},
		{
			// The #544 case: a replacement container's ADD recreated the pair
			// under the same name while its predecessor was still
			// terminating. The predecessor's DEL must not reclaim it.
			name:    "a successor has taken the attachment over",
			alias:   testOwnerB,
			ownerID: testOwnerA,
			want:    false,
		},
		{
			// Created before this stamp existed, or by an ADD that failed
			// before reaching it. Refusing these would leak an interface per
			// attachment with nothing left to reclaim it.
			name:    "an unstamped interface is claimable by anyone",
			alias:   "",
			ownerID: testOwnerA,
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := OwnedBy(linkWithAlias(tc.alias), tc.ownerID); got != tc.want {
				t.Errorf("OwnedBy(alias=%q, ownerID=%q) = %v, want %v", tc.alias, tc.ownerID, got, tc.want)
			}
		})
	}
}
