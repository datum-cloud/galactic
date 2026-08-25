// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"testing"

	"go.datum.net/galactic/internal/model"
)

// TestPeerFromDesired_RouteReflectorClientFollowsExplicitFlag is the
// regression test for a bug where the RouteReflectorClient flag was derived
// from listenPort > 0 (whether this instance accepts inbound BGP) instead of
// from an explicit reflector signal. The two properties are independent:
// listenPort only controls the inbound listener, and must not by itself mark
// every peer as a route-reflector client.
func TestPeerFromDesired_RouteReflectorClientFollowsExplicitFlag(t *testing.T) {
	tests := []struct {
		name       string
		reflector  bool
		wantClient bool
	}{
		{name: "reflector disabled", reflector: false, wantClient: false},
		{name: "reflector enabled", reflector: true, wantClient: true},
	}

	desired := model.DesiredPeer{Address: "2001:db8:ff01::1", PeerASN: 65000}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peer := peerFromDesired(desired, "", tc.reflector)

			gotClient := peer.RouteReflector != nil && peer.RouteReflector.RouteReflectorClient
			if gotClient != tc.wantClient {
				t.Errorf("peerFromDesired() RouteReflectorClient = %v, want %v", gotClient, tc.wantClient)
			}
		})
	}
}
