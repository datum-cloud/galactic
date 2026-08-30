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

// TestPeerFromDesired_UpdateSourceOverridesLocalAddress is the regression
// test for BGPPeer.spec.updateSource being silently ignored: peerFromDesired
// always stamped the process-wide localAddress onto every peer's
// Transport.LocalAddress, with no way for a single peer to source from
// somewhere else. This broke a peer reached over the node's own eth0/bond0
// link instead of the SRv6 loopback -- its session kept sourcing from the
// loopback regardless of what the CR said, and could never establish since
// the loopback has no route back from a site the SRv6 underlay doesn't
// reach.
func TestPeerFromDesired_UpdateSourceOverridesLocalAddress(t *testing.T) {
	const (
		processDefault = "2607:ed40:1ff::3"
		perPeer        = "2607:f740:100::635"
	)

	tests := []struct {
		name string
		peer model.DesiredPeer
		want string
	}{
		{
			name: "no updateSource falls back to the process-wide default",
			peer: model.DesiredPeer{Address: testSID1, PeerASN: 65000},
			want: processDefault,
		},
		{
			name: "updateSource overrides the process-wide default",
			peer: model.DesiredPeer{Address: testSID1, PeerASN: 65000, UpdateSource: perPeer},
			want: perPeer,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peer := peerFromDesired(tc.peer, processDefault, false)

			if got := peer.Transport.LocalAddress; got != tc.want {
				t.Errorf("peerFromDesired() Transport.LocalAddress = %q, want %q", got, tc.want)
			}
		})
	}
}
