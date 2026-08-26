// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"testing"

	"go.datum.net/galactic/internal/model"
)

const (
	testPeerAddrV4 = "192.0.2.1"
	testPeerAddrV6 = "2607:ed40:1fb::2"
)

// TestAllDesiredPeersPresent verifies the no-op reconcile guard used by
// BGPRouterReconciler.Reconcile: a runtime that reports Healthy but has
// silently lost a desired peer (e.g. a GC cycle dropped it from GoBGP's live
// state without the desired config's hash ever changing) must not be
// treated as a true no-op.
func TestAllDesiredPeersPresent(t *testing.T) {
	tests := []struct {
		name  string
		peers []model.DesiredPeer
		rs    model.RuntimeStatus
		want  bool
	}{
		{
			name:  "no desired peers",
			peers: nil,
			rs:    model.RuntimeStatus{},
			want:  true,
		},
		{
			name:  "all desired peers present",
			peers: []model.DesiredPeer{{Address: testPeerAddrV6}, {Address: testPeerAddrV4}},
			rs: model.RuntimeStatus{Peers: []model.PeerStatus{
				{Address: testPeerAddrV6}, {Address: testPeerAddrV4},
			}},
			want: true,
		},
		{
			name:  "peer missing from runtime status (dropped without a hash change)",
			peers: []model.DesiredPeer{{Address: testPeerAddrV6}, {Address: testPeerAddrV4}},
			rs: model.RuntimeStatus{Peers: []model.PeerStatus{
				{Address: testPeerAddrV4},
			}},
			want: false,
		},
		{
			name:  "address normalization matches leading-zero IPv6 forms",
			peers: []model.DesiredPeer{{Address: "2607:ed40:01fb::2"}},
			rs: model.RuntimeStatus{Peers: []model.PeerStatus{
				{Address: testPeerAddrV6},
			}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allDesiredPeersPresent(tt.peers, tt.rs); got != tt.want {
				t.Errorf("allDesiredPeersPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}
