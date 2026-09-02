// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"go.datum.net/galactic/internal/model"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Event Reason values PeerStateEventEmitter raises. Exported as constants
// (rather than inline literals) so callers — and this package's own tests —
// have one shared spelling to filter/assert on, e.g.
// `kubectl get events --field-selector reason=SessionDown`.
const (
	ReasonSessionEstablished = "SessionEstablished"
	ReasonSessionDown        = "SessionDown"
)

// peerEventQueueSize bounds PeerStateEventEmitter's internal queue. It's
// arbitrary but generous relative to how often real peer flaps happen; once
// full, ObservePeerStateChange drops the transition (logging it) rather than
// blocking, since it runs synchronously on the reporting runtime's own
// peer-event watcher goroutine — see PeerStateEventEmitter's doc comment.
const peerEventQueueSize = 64

// PeerStateEventEmitter turns real-time BGP peer FSM transitions
// (model.PeerStateChange, as reported by a RouterRuntime's own peer-event
// watcher — see internal/runtime/gobgp/peer_monitor.go) into Kubernetes
// Events on the corresponding BGPPeer object. It implements
// model.PeerStateObserver and manager.Runnable, so the controller-runtime
// manager owns its worker goroutine's lifecycle the same way it owns every
// reconciler — see docs/plans/router-bgp-peer-session-events.md.
//
// This is deliberately independent of BGPRouterReconciler's periodic
// (peerStatusRequeue) BGPPeer.Status update: that keeps the CRD's status
// current on a poll; this reacts to each transition immediately, including
// ones that revert between two polls and would otherwise leave no trace.
type PeerStateEventEmitter struct {
	Client   client.Client
	Recorder events.EventRecorder

	queue chan model.PeerStateChange
}

// NewPeerStateEventEmitter returns a PeerStateEventEmitter ready to be
// registered with a manager (mgr.Add) and passed to
// gobgp.NewRuntimeFactory as a model.PeerStateObserver.
func NewPeerStateEventEmitter(c client.Client, recorder events.EventRecorder) *PeerStateEventEmitter {
	return &PeerStateEventEmitter{
		Client:   c,
		Recorder: recorder,
		queue:    make(chan model.PeerStateChange, peerEventQueueSize),
	}
}

// ObservePeerStateChange implements model.PeerStateObserver. It must never
// block — see the type doc comment — so it only enqueues change for Start's
// worker loop to process, dropping (and logging) it if the queue is ever
// full rather than stalling the calling runtime's session convergence.
func (e *PeerStateEventEmitter) ObservePeerStateChange(change model.PeerStateChange) {
	select {
	case e.queue <- change:
	default:
		slog.Warn("peer state event queue full; dropping transition",
			"router", change.RouterKey, "peer", change.Address,
			"from", change.From, "to", change.To)
	}
}

// Start implements manager.Runnable. It drains the queue until ctx is done.
func (e *PeerStateEventEmitter) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case change := <-e.queue:
			e.emit(ctx, change)
		}
	}
}

// emit resolves change to a BGPPeer and raises an Event on it, when the
// transition is one peerStateEventDetails considers worth surfacing.
func (e *PeerStateEventEmitter) emit(ctx context.Context, change model.PeerStateChange) {
	eventType, reason, message, ok := peerStateEventDetails(change)
	if !ok {
		return
	}
	logger := log.FromContext(ctx)

	router := &bgpv1alpha1.BGPRouter{}
	if err := e.Client.Get(ctx, change.RouterKey, router); err != nil {
		logger.V(1).Info("peer state event: get BGPRouter failed, skipping",
			"router", change.RouterKey, "err", err)
		return
	}

	peers, err := peersForRouter(ctx, e.Client, router)
	if err != nil {
		logger.V(1).Info("peer state event: list BGPPeers failed, skipping",
			"router", change.RouterKey, "err", err)
		return
	}

	for _, peer := range peers {
		if normalizeIP(peer.Spec.Address) != normalizeIP(change.Address) {
			continue
		}
		// action mirrors reason: this emitter only reports an observed
		// transition, it doesn't itself take a distinct "action" the
		// EventsV1 Action field would otherwise describe.
		e.Recorder.Eventf(peer, nil, eventType, reason, reason, "%s", message)
		return
	}
	logger.V(1).Info("peer state event: no matching BGPPeer, skipping",
		"router", change.RouterKey, "peer", change.Address)
}

// peerStateEventDetails reports the Event fields for change, and false when
// change isn't one of the transitions this emitter surfaces. Only crossing
// into or out of Established is reported: every other FSM hop (Idle,
// Connect, Active, OpenSent, OpenConfirm cycling while a session has never
// reached Established, e.g. initial connection setup or backoff) is normal
// and would otherwise flood `kubectl get events` for any peer that simply
// isn't up yet.
func peerStateEventDetails(change model.PeerStateChange) (eventType, reason, message string, ok bool) {
	switch {
	case change.To == model.BGPPeerStateEstablished:
		return corev1.EventTypeNormal, ReasonSessionEstablished,
			fmt.Sprintf("BGP session with %s (AS %d) transitioned to Established.",
				change.Address, change.PeerASN), true

	case change.From == model.BGPPeerStateEstablished:
		msg := fmt.Sprintf("BGP session with %s (AS %d) went from Established to %s",
			change.Address, change.PeerASN, change.To)
		detail := change.DisconnectMessage
		if detail == "" {
			detail = change.DisconnectReason
		}
		if detail != "" {
			msg += fmt.Sprintf(" (reason: %s)", detail)
		}
		return corev1.EventTypeWarning, ReasonSessionDown, msg + ".", true

	default:
		return "", "", "", false
	}
}
