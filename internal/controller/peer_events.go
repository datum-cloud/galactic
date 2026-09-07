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

// Event reason values this emitter raises, named so callers and tests share one
// spelling to filter and assert on.
const (
	ReasonSessionEstablished = "SessionEstablished"
	ReasonSessionDown        = "SessionDown"
)

// peerEventQueueSize bounds the emitter's internal queue: generous relative to
// how often real flaps happen. Once full, an observed transition is dropped and
// logged rather than blocking, since observation runs synchronously on the
// reporting runtime's own watcher goroutine.
const peerEventQueueSize = 64

// PeerStateEventEmitter turns real-time peer FSM transitions, as reported by a
// runtime's own watcher, into Kubernetes events on the corresponding BGPPeer.
// It is both an observer and a manager runnable, so the manager owns its worker
// goroutine's lifecycle the way it owns every reconciler.
//
// It is deliberately independent of the reconciler's periodic status update:
// that keeps the CRD current on a poll, while this reacts to each transition
// immediately, including ones that revert between polls and would otherwise
// leave no trace.
type PeerStateEventEmitter struct {
	Client   client.Client
	Recorder events.EventRecorder

	queue chan model.PeerStateChange
}

// NewPeerStateEventEmitter returns an emitter ready to be registered with a
// manager and passed to the runtime factory as an observer.
func NewPeerStateEventEmitter(c client.Client, recorder events.EventRecorder) *PeerStateEventEmitter {
	return &PeerStateEventEmitter{
		Client:   c,
		Recorder: recorder,
		queue:    make(chan model.PeerStateChange, peerEventQueueSize),
	}
}

// ObservePeerStateChange enqueues change for the worker loop. It must never
// block, so a full queue drops and logs the change rather than stalling the
// calling runtime's session convergence.
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
		// The action mirrors the reason: this emitter reports an observed
		// transition rather than taking a distinct action of its own.
		e.Recorder.Eventf(peer, nil, eventType, reason, reason, "%s", message)
		return
	}
	logger.V(1).Info("peer state event: no matching BGPPeer, skipping",
		"router", change.RouterKey, "peer", change.Address)
}

// peerStateEventDetails reports the event fields for change, and false when
// change is not a transition this emitter surfaces.
//
// Only crossing into or out of Established is reported. Every other FSM hop
// while a session has never come up is normal, and reporting them would flood
// the event stream for any peer that simply is not up yet.
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
