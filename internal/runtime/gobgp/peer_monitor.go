// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/model"
)

// labelPeer is the metric label naming a BGP peer by its neighbor address.
const labelPeer = "peer"

// peerSessionDrops counts, per BGPRouter and peer, the sessions that left
// Established. It is driven by GoBGP's peer event stream rather than the
// controller's 30s status poll, so a session that drops and re-establishes
// between two polls is still counted; a rising rate means a flapping session.
var peerSessionDrops = metrics.NewCounterVec(prometheus.CounterOpts{
	Name: "galactic_router_peer_session_drops_total",
	Help: "BGP sessions to a peer that left the Established state.",
}, []string{labelRouter, labelPeer})

// selfResetGrace is how long after the runtime itself deletes or updates a
// peer that peer's next transition out of Established is attributed to the
// runtime rather than counted as a drop. GoBGP stops a peer it deletes, and
// restarts one whose update needs a fresh OPEN, signalling Idle either way;
// counting those would turn config churn into a flapping alert. An update
// that leaves the session up signals nothing, so the mark is time-bounded
// rather than left to swallow a later real drop.
const selfResetGrace = 30 * time.Second

// canonicalPeerAddr formats a peer address the way GoBGP's peer events do, so
// every metric labels a peer identically.
func canonicalPeerAddr(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil {
		return a.String()
	}
	return addr
}

// markSelfReset records that the runtime is about to delete or update the
// peer at addr, so the transition it causes is not counted as a drop.
func (r *GoBGPRuntime) markSelfReset(addr string) {
	r.peerStateMu.Lock()
	defer r.peerStateMu.Unlock()
	if r.selfResetPeers == nil {
		r.selfResetPeers = make(map[string]time.Time)
	}
	r.selfResetPeers[canonicalPeerAddr(addr)] = time.Now()
}

// startPeerMonitor starts the shared peer FSM watcher goroutine, once per
// runtime lifetime, as startRIBMonitor does for best-path events. A node can
// host many peers, so one goroutine per peer would not scale, and the watch API
// is already shared across a server's peers.
//
// It exists because the log level only controls GoBGP's internal logger, which
// is discarded whatever the level, so without this watcher session transitions
// never appear in this process's output at all. The periodic status update
// reflects the current state into the CRD but never logs a transition, and can
// miss one entirely if it reverts between two polls.
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

// onPeerUpdate logs one peer's FSM transition, diffing against the last
// observed state so a re-signal of the same state, which GoBGP can emit more
// than once, produces no duplicate line. It also notifies the observer, which
// raises Kubernetes events on the corresponding BGPPeer.
//
// The end-of-init event is skipped: it marks the end of the initial peer-list
// replay to a new watcher, not an FSM transition.
//
// The event carries only the peer's new state, not its old one, so the
// last-observed map is this runtime's own record of what it last saw rather
// than something GoBGP hands over.
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
	markedAt, marked := r.selfResetPeers[addr]
	delete(r.selfResetPeers, addr)
	r.peerStateMu.Unlock()
	selfReset := marked && time.Since(markedAt) < selfResetGrace

	if !seen {
		prev = model.BGPPeerStateIdle
	}

	fields := []any{
		labelRouter, r.key.String(),
		"peer", addr,
		"asn", ev.Peer.Conf.PeerASN,
		"from", prev,
		"to", next,
	}
	if next == model.BGPPeerStateEstablished {
		// Create the series at 0 before the first drop, so increase() over
		// a window sees that drop instead of starting from it. A session
		// that establishes and drops within one scrape interval is still
		// first scraped at 1, and that one drop is missed.
		peerSessionDrops.WithLabelValues(r.key.String(), addr).Add(0)
	}
	leavingEstablished := next != model.BGPPeerStateEstablished && prev == model.BGPPeerStateEstablished
	if leavingEstablished {
		if !selfReset {
			peerSessionDrops.WithLabelValues(r.key.String(), addr).Inc()
		}
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
		// A zero disconnect reason means GoBGP attached none. Leave it
		// unset rather than pass through the enum's zero-value name.
		if ev.Peer.State.DisconnectReason != 0 {
			change.DisconnectReason = ev.Peer.State.DisconnectReason.String()
		}
		change.DisconnectMessage = ev.Peer.State.DisconnectMessage
	}
	r.observer.ObservePeerStateChange(change)
}

// bgpFSMStateToModel converts a GoBGP FSM state, as carried by the peer-event
// stream, to the model's own. It mirrors the conversion in runtime.go for the
// analogous but distinctly typed field the peer-listing API returns for the same
// six states.
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
