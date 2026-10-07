// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"testing"

	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

func TestArgumentForTableID(t *testing.T) {
	const base = vrf.SidecarTableIDBase
	cases := []struct {
		name    string
		tableID uint32
		want    uint16
		wantErr bool
	}{
		{name: "first sidecar table id", tableID: base + 1, want: 1},
		{name: "another sidecar table id", tableID: base + 3, want: 3},
		{name: "argument max boundary", tableID: base + uformat.ArgumentMax, want: uformat.ArgumentMax},
		{name: "base itself is out of range (Argument 0 is reserved)", tableID: base, wantErr: true},
		{name: "past the 12-bit Argument range", tableID: base + uformat.ArgumentMax + 1, wantErr: true},
		// The host allocates these, so a sidecar must never derive an Argument
		// from one.
		{name: "host table id 1", tableID: 1, wantErr: true},
		{name: "last host table id", tableID: vrf.HostTableIDMax, wantErr: true},
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

// TestEgressVethNames covers the two properties ensureEgressDatapath and
// removeEgressDatapath both depend on to ever find the same pair twice:
// deterministic (so a later call derives the identical names a former
// call used) and collision-free across different table ids (so two VPCs
// sharing this node never contend for the same interface names).
func TestEgressVethNames(t *testing.T) {
	inner1, peer1 := egressVethNames(2)
	inner2, peer2 := egressVethNames(2)
	if inner1 != inner2 || peer1 != peer2 {
		t.Fatalf("egressVethNames(2) is not deterministic: (%s,%s) vs (%s,%s)", inner1, peer1, inner2, peer2)
	}
	if inner1 == peer1 {
		t.Fatalf("egressVethNames(2) returned identical inner/peer names %q", inner1)
	}

	otherInner, otherPeer := egressVethNames(3)
	if inner1 == otherInner || peer1 == otherPeer {
		t.Fatalf("egressVethNames collided across table ids: table 2 = (%s,%s), table 3 = (%s,%s)",
			inner1, peer1, otherInner, otherPeer)
	}

	maxInner, maxPeer := egressVethNames(sidecarTableIDMax)
	for _, name := range []string{inner1, peer1, otherInner, otherPeer, maxInner, maxPeer} {
		if len(name) > unix.IFNAMSIZ-1 {
			t.Errorf("egressVethNames produced %q, %d bytes -- too long for IFNAMSIZ (%d)", name, len(name), unix.IFNAMSIZ)
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
