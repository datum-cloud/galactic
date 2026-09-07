// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package model

import (
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// PeerStateChange is one observed BGP peer FSM transition, reported by a
// runtime's own watcher to an observer in real time. That is independent of, and
// faster than, the periodic status update driven by polling, which can miss a
// transition entirely if it reverts between two polls.
type PeerStateChange struct {
	// RouterKey identifies the BGPRouter this peer belongs to.
	RouterKey types.NamespacedName
	// Address is the peer's neighbor address, as configured on DesiredPeer.
	Address string
	// PeerASN is the peer's autonomous system number, when known.
	PeerASN int64
	// From and To are the FSM states either side of this transition. From is
	// Idle for the first transition observed for a peer, the underlying watch
	// API not reporting a prior state.
	From, To BGPPeerState
	// DisconnectReason and DisconnectMessage describe why a session dropped out
	// of Established, when the runtime supplies them. Both are empty for every
	// other transition.
	DisconnectReason  string
	DisconnectMessage string
	// Time is when the runtime observed this transition.
	Time time.Time
}

// PeerStateObserver receives peer FSM transitions as a runtime detects them.
// Implementations must not block: the callback runs synchronously on the
// runtime's own watcher goroutine, so a slow one stalls that runtime's session
// convergence for every peer it manages, not just the one that transitioned.
type PeerStateObserver interface {
	ObservePeerStateChange(PeerStateChange)
}
