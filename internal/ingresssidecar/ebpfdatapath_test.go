// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"testing"

	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

func TestArgumentForTableID(t *testing.T) {
	cases := []struct {
		name    string
		tableID uint32
		want    uint16
		wantErr bool
	}{
		{name: "typical small table id", tableID: 1, want: 1},
		{name: "another typical table id", tableID: 3, want: 3},
		{name: "argument min boundary", tableID: uint32(uformat.ArgumentMin), want: uint16(uformat.ArgumentMin)},
		{name: "argument max boundary", tableID: uint32(uformat.ArgumentMax), want: uint16(uformat.ArgumentMax)},
		{name: "zero table id is out of range (Argument 0 is reserved)", tableID: 0, wantErr: true},
		{name: "table id past the 12-bit Argument range", tableID: uint32(uformat.ArgumentMax) + 1, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := argumentForTableID(tc.tableID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("argumentForTableID(%d) = %d, nil; want an error", tc.tableID, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("argumentForTableID(%d) unexpected error: %v", tc.tableID, err)
			}
			if got != tc.want {
				t.Fatalf("argumentForTableID(%d) = %d, want %d", tc.tableID, got, tc.want)
			}
		})
	}
}

// TestMarkForTableID mirrors TestArgumentForTableID's own table-driven
// shape: markForTableID is a straight uint32-to-uint32 passthrough (no
// truncation risk the way Argument's 12-bit range has), so its only real
// edge case is the explicit tableID-0 rejection documented on the function
// itself.
func TestMarkForTableID(t *testing.T) {
	cases := []struct {
		name    string
		tableID uint32
		want    uint32
		wantErr bool
	}{
		{name: "typical small table id", tableID: 1, want: 1},
		{name: "another typical table id", tableID: 3, want: 3},
		{name: "large table id", tableID: 1 << 20, want: 1 << 20},
		{name: "zero table id is rejected (would collide with an unmarked skb)", tableID: 0, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := markForTableID(tc.tableID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("markForTableID(%d) = %d, nil; want an error", tc.tableID, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("markForTableID(%d) unexpected error: %v", tc.tableID, err)
			}
			if got != tc.want {
				t.Fatalf("markForTableID(%d) = %d, want %d", tc.tableID, got, tc.want)
			}
		})
	}
}

// TestTrunkNamesAreFixedAndDistinct documents, in code, the "no per-pod
// uniqueness needed" decision on trunkInnerName/trunkPeerName's own doc
// comment: they are plain constants, not derived from any per-pod
// identifier, and must still be distinct from each other and fit
// IFNAMSIZ.
func TestTrunkNamesAreFixedAndDistinct(t *testing.T) {
	if trunkInnerName == trunkPeerName {
		t.Fatalf("trunkInnerName and trunkPeerName are identical: %q", trunkInnerName)
	}
	for _, name := range []string{trunkInnerName, trunkPeerName} {
		if len(name) > unix.IFNAMSIZ-1 {
			t.Errorf("trunk name %q is %d bytes -- too long for IFNAMSIZ (%d)", name, len(name), unix.IFNAMSIZ)
		}
	}
}

// TestIngressSidecarBlockIsReserved pins down ingressSidecarBlock's own
// value against uformat's own limits: it must be a valid Block (fits the
// 48-bit field Register/ValidateBlock enforce) and, per its own doc
// comment's collision-avoidance reasoning, it must be the maximum such
// value, not merely *a* valid one -- a regression here would silently
// narrow the "no real fabric would assign this" guarantee the doc comment
// promises.
func TestIngressSidecarBlockIsReserved(t *testing.T) {
	if err := uformat.ValidateBlock(ingressSidecarBlock); err != nil {
		t.Fatalf("ingressSidecarBlock is not a valid uSID Block: %v", err)
	}
	if ingressSidecarBlock != uformat.BlockMax {
		t.Fatalf("ingressSidecarBlock = %#x, want the reserved maximum %#x", ingressSidecarBlock, uint64(uformat.BlockMax))
	}
}
