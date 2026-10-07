// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vrf

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestNextFreeTableID(t *testing.T) {
	used := func(ids ...uint32) map[uint32]struct{} {
		m := make(map[uint32]struct{}, len(ids))
		for _, id := range ids {
			m[id] = struct{}{}
		}
		return m
	}
	cases := []struct {
		name     string
		used     map[uint32]struct{}
		min, max uint32
		want     uint32
		wantErr  bool
	}{
		{name: "empty host range starts at its minimum", used: used(), min: HostTableIDMin, max: HostTableIDMax, want: 1},
		{name: "skips used ids", used: used(1, 2), min: HostTableIDMin, max: HostTableIDMax, want: 3},
		{name: "skips the kernel's reserved tables", used: used(252), min: 252, max: 300, want: 256},
		{
			name: "allocates inside a range above the minimum", used: used(),
			min: SidecarTableIDBase + 1, max: SidecarTableIDBase + 0xFFF, want: SidecarTableIDBase + 1,
		},
		{name: "full range", used: used(10, 11), min: 10, max: 11, wantErr: true},
		{
			name: "range of only reserved tables", used: used(),
			min: unix.RT_TABLE_DEFAULT, max: unix.RT_TABLE_LOCAL, wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nextFreeTableID(tc.used, tc.min, tc.max)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("nextFreeTableID = %d, nil; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("nextFreeTableID: %v", err)
			}
			if got != tc.want {
				t.Errorf("nextFreeTableID = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestNextFreeTableID_HostAndSidecarNeverOverlap checks the host and the
// ingress sidecar never pick the same table ID. They allocate in separate
// network namespaces, each seeing none of the other's VRFs, but write the same
// egress_route_table keyed by table ID.
func TestNextFreeTableID_HostAndSidecarNeverOverlap(t *testing.T) {
	host, err := nextFreeTableID(map[uint32]struct{}{}, HostTableIDMin, HostTableIDMax)
	if err != nil {
		t.Fatalf("host allocation: %v", err)
	}
	sidecar, err := nextFreeTableID(map[uint32]struct{}{}, SidecarTableIDBase+1, SidecarTableIDBase+0xFFF)
	if err != nil {
		t.Fatalf("sidecar allocation: %v", err)
	}
	if host == sidecar {
		t.Fatalf("host and sidecar both allocated table %d from empty namespaces", host)
	}
	if HostTableIDMax >= SidecarTableIDBase {
		t.Fatalf("HostTableIDMax %d reaches SidecarTableIDBase %d", HostTableIDMax, SidecarTableIDBase)
	}
}
