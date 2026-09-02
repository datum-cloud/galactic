// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package model

import (
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// PeerStateChange is a single observed BGP peer FSM transition, reported by
// a RouterRuntime's own peer-event watcher (e.g. internal/runtime/gobgp's
// GoBGP-native WatchEvent/WatchPeer subscription) to a PeerStateObserver in
// real time — independent of, and faster than, the periodic BGPPeer.Status
// update driven by RuntimeManager.Status polling, which can miss a
// transition entirely if it reverts between two polls.
type PeerStateChange struct {
	// RouterKey identifies the BGPRouter this peer belongs to.
	RouterKey types.NamespacedName
	// Address is the peer's neighbor address, as configured on DesiredPeer.
	Address string
	// PeerASN is the peer's autonomous system number, when known.
	PeerASN int64
	// From and To are the FSM states either side of this transition. From is
	// BGPPeerStateIdle for the first transition observed for a peer, since
	// the underlying watch API does not report a peer's prior state.
	From, To BGPPeerState
	// DisconnectReason and DisconnectMessage describe why a session dropped
	// out of Established, when the runtime supplies them. Both are empty for
	// every other transition.
	DisconnectReason  string
	DisconnectMessage string
	// Time is when the runtime observed this transition.
	Time time.Time
}

// PeerStateObserver receives BGP peer FSM state transitions as a
// RouterRuntime detects them. Implementations must not block:
// ObservePeerStateChange is called synchronously on the runtime's own
// peer-event watcher goroutine, so a slow or blocking implementation would
// stall that runtime's session convergence for every peer it manages, not
// just the one that just transitioned.
type PeerStateObserver interface {
	ObservePeerStateChange(PeerStateChange)
}
