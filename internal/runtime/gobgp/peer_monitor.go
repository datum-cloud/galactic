// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"log/slog"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"

	"go.datum.net/galactic/internal/model"
)

// startPeerMonitor starts the shared peer FSM transition watcher goroutine
// once per GoBGPRuntime lifetime, the same one-shared-goroutine-per-runtime
// pattern startRIBMonitor uses for EVPN best-path — a node can host many
// peers, so a dedicated goroutine per peer would not scale, and GoBGP's own
// WatchEvent/WatchPeer API is already shared across all of a BgpServer's
// peers.
//
// This exists because GALACTIC_ROUTER's LogLevel only controls GoBGP's
// internal logger, which is wired to io.Discard regardless of level (see
// buildServerOptions in server.go) — so without this watcher, peer session
// transitions (Idle → Connect → ... → Established, and drops back down)
// never appear in this process's log output at all. The periodic
// (peerStatusRequeue-interval) BGPPeer.Status update in
// internal/controller/bgprouter_controller.go's updatePeerStatuses reflects
// the *current* state into the CR, but never logs a transition, and can miss
// one entirely if it reverts between two polls.
func (r *GoBGPRuntime) startPeerMonitor(b *gobgpserver.BgpServer) {
	if r.srvCtx == nil {
		slog.Info("startPeerMonitor: skipping — srvCtx is nil")
		return
	}
	r.peerMonitorOnce.Do(func() {
		slog.Info("startPeerMonitor: launching shared watchPeerEvents goroutine")
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.watchPeerEvents(r.srvCtx, b)
		}()
	})
}

func (r *GoBGPRuntime) watchPeerEvents(ctx context.Context, b *gobgpserver.BgpServer) {
	watchErr := b.WatchEvent(ctx, gobgpserver.WatchEventMessageCallbacks{
		OnPeerUpdate: func(ev *apiutil.WatchEventMessage_PeerEvent, ts time.Time) {
			r.onPeerUpdate(ev, ts)
		},
	}, gobgpserver.WatchPeer())
	if watchErr != nil {
		slog.Error("watchPeerEvents: WatchEvent returned error", "err", watchErr)
	}
}

// onPeerUpdate logs an FSM state transition for a single peer, diffing
// against lastPeerState so a re-signal of the same state (GoBGP can emit
// more than one event per state) doesn't produce a duplicate log line. It
// also notifies r.observer (if set) of the same transition, which
// PeerStateEventEmitter (internal/controller) uses to raise Kubernetes
// Events on the corresponding BGPPeer — see docs/plans/router-bgp-peer-
// session-events.md.
//
// PEER_EVENT_END_OF_INIT is skipped: it marks the end of GoBGP's initial
// peer-list replay to a new watcher, not an FSM transition (mirrors how
// bmp.go's own peer up/down detection filters it).
//
// The exported apiutil.WatchEventMessage_PeerEvent only carries the peer's
// new state, not its old one (GoBGP's internal watchEventPeer has an
// OldState field, but WatchEvent doesn't forward it through this callback)
// — so lastPeerState is this runtime's own record of "what did we last see
// for this peer," rather than something GoBGP hands us directly.
func (r *GoBGPRuntime) onPeerUpdate(ev *apiutil.WatchEventMessage_PeerEvent, ts time.Time) {
	if ev == nil || ev.Type == apiutil.PEER_EVENT_END_OF_INIT {
		return
	}

	addr := ev.Peer.Conf.NeighborAddress.String()
	next := bgpFSMStateToModel(ev.Peer.State.SessionState)

	r.peerStateMu.Lock()
	prev, seen := r.lastPeerState[addr]
	if seen && prev == next {
		r.peerStateMu.Unlock()
		return
	}
	r.lastPeerState[addr] = next
	r.peerStateMu.Unlock()

	if !seen {
		prev = model.BGPPeerStateIdle
	}

	fields := []any{
		"router", r.key.String(),
		"peer", addr,
		"asn", ev.Peer.Conf.PeerASN,
		"from", prev,
		"to", next,
	}
	leavingEstablished := next != model.BGPPeerStateEstablished && prev == model.BGPPeerStateEstablished
	if leavingEstablished {
		fields = append(fields,
			"disconnectReason", ev.Peer.State.DisconnectReason,
			"disconnectMessage", ev.Peer.State.DisconnectMessage,
		)
	}
	slog.Info("bgp peer state transition", fields...)

	if r.observer == nil {
		return
	}
	change := model.PeerStateChange{
		RouterKey: r.key,
		Address:   addr,
		PeerASN:   int64(ev.Peer.Conf.PeerASN),
		From:      prev,
		To:        next,
		Time:      ts,
	}
	if leavingEstablished {
		// DisconnectReason's zero value (DISCONNECT_REASON_UNSPECIFIED) means
		// GoBGP didn't attach a reason — leave it unset rather than passing
		// through the enum's zero-value name.
		if ev.Peer.State.DisconnectReason != 0 {
			change.DisconnectReason = ev.Peer.State.DisconnectReason.String()
		}
		change.DisconnectMessage = ev.Peer.State.DisconnectMessage
	}
	r.observer.ObservePeerStateChange(change)
}

// bgpFSMStateToModel converts a GoBGP FSM state, as carried by the
// WatchEvent/OnPeerUpdate peer-event stream, to a model.BGPPeerState. This
// mirrors fsmStateToModel in runtime.go, which converts the analogous but
// distinctly-typed state field GoBGP's ListPeer API returns
// (api.PeerState_SessionState) for the same six FSM states.
func bgpFSMStateToModel(state bgp.FSMState) model.BGPPeerState {
	switch state {
	case bgp.BGP_FSM_IDLE:
		return model.BGPPeerStateIdle
	case bgp.BGP_FSM_CONNECT:
		return model.BGPPeerStateConnect
	case bgp.BGP_FSM_ACTIVE:
		return model.BGPPeerStateActive
	case bgp.BGP_FSM_OPENSENT:
		return model.BGPPeerStateOpenSent
	case bgp.BGP_FSM_OPENCONFIRM:
		return model.BGPPeerStateOpenConfirm
	case bgp.BGP_FSM_ESTABLISHED:
		return model.BGPPeerStateEstablished
	default:
		return model.BGPPeerStateIdle
	}
}
