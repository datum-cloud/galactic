// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"net/netip"
	"testing"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
)

// TestNodeSIDBase checks the source SID derived from a node's locator: its
// Block and Node-ID with the End.DT46 Function and no Argument.
func TestNodeSIDBase(t *testing.T) {
	tests := []struct {
		name      string
		locator   string
		want      string
		wantError bool
	}{
		{"NodeOne", "2001:db8:4135:1::/64", "2001:db8:4135:1:e000::", false},
		{"NodeHigh", "2001:db8:aa:1f2::/64", "2001:db8:aa:1f2:e000::", false},
		{"IPv4", "192.0.2.0/24", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeSIDBase(netip.MustParsePrefix(tt.locator))
			if (err != nil) != tt.wantError {
				t.Fatalf("nodeSIDBase(%s) error = %v, wantError = %t", tt.locator, err, tt.wantError)
			}
			if !tt.wantError && got != netip.MustParseAddr(tt.want) {
				t.Fatalf("nodeSIDBase(%s) = %s, want %s", tt.locator, got, tt.want)
			}
		})
	}
}

// TestHandoffBlocked checks that a routed link's block is reported for the
// Fabric destinations of its claim only, as of the last Read, and that the
// caller's copy is its own.
func TestHandoffBlocked(t *testing.T) {
	m, err := New(Config{Kernel: &Kernel{}, Node: testNodeUnit})
	if err != nil {
		t.Fatal(err)
	}
	key := module.ClaimKey{Node: testNodeUnit, VPC: unitVPC, AttachmentUID: "envoy-1"}
	block := module.Blocked{Reason: workerv1alpha1.ReasonRoutedLinkEgressUnavailable, Message: "not first"}
	m.blocked[unitVPC] = map[module.ClaimKey]module.Blocked{key: block}
	scope := module.Scope{VPC: unitVPC}
	tests := []struct {
		name string
		mode workerv1alpha1.Mode
		want bool
	}{
		{"Fabric", workerv1alpha1.Mode_MODE_FABRIC, true},
		{"Local", workerv1alpha1.Mode_MODE_LOCAL, false},
		{"Unspecified", workerv1alpha1.Mode_MODE_UNSPECIFIED, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := m.HandoffBlocked(scope, tt.mode)[key]
			if ok != tt.want || (ok && got != block) {
				t.Fatalf("HandoffBlocked(%s) = %+v (%t), want present %t", tt.mode, got, ok, tt.want)
			}
		})
	}
	got := m.HandoffBlocked(scope, workerv1alpha1.Mode_MODE_FABRIC)
	delete(got, key)
	if _, ok := m.HandoffBlocked(scope, workerv1alpha1.Mode_MODE_FABRIC)[key]; !ok {
		t.Fatal("changing the returned map changed the module's")
	}
	if b := m.HandoffBlocked(module.Scope{VPC: "0000081"}, workerv1alpha1.Mode_MODE_FABRIC); len(b) != 0 {
		t.Fatalf("another scope reports %v", b)
	}
}

// The node and VPC of the unit tests.
const (
	testNodeUnit = "node-unit"
	unitVPC      = "0000080"
)
