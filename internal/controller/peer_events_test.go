// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/model"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const testEmitterPeerAddr = "2607:ed40:1fb::2"

// newPeerEventsTestClient returns a fake client, with the BGPPeerByRouterName
// index PeerStateEventEmitter.emit relies on (via peersForRouter) pre-
// registered, seeded with router and peer.
func newPeerEventsTestClient(t *testing.T, router *bgpv1alpha1.BGPRouter, peer *bgpv1alpha1.BGPPeer) client.Client {
	t.Helper()
	scheme := newRuleTestScheme(t)
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&bgpv1alpha1.BGPPeer{}, BGPPeerByRouterName, func(obj client.Object) []string {
			p, ok := obj.(*bgpv1alpha1.BGPPeer)
			if !ok || p.Spec.RouterRef == nil {
				return nil
			}
			return []string{p.Spec.RouterRef.Name}
		}).
		WithObjects(router, peer).
		Build()
}

func testRouterAndPeer() (*bgpv1alpha1.BGPRouter, *bgpv1alpha1.BGPPeer) {
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "r1"},
	}
	peer := &bgpv1alpha1.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "peer-1"},
		Spec: bgpv1alpha1.BGPPeerSpec{
			RouterTarget: bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: router.Name}},
			Address:      testEmitterPeerAddr,
			PeerASN:      65010,
		},
	}
	return router, peer
}

// readFakeEvent drains recorder.Events with a short timeout, returning ""
// (rather than blocking forever) when no event was emitted.
func readFakeEvent(t *testing.T, recorder *events.FakeRecorder) string {
	t.Helper()
	select {
	case e := <-recorder.Events:
		return e
	case <-time.After(time.Second):
		return ""
	}
}

// TestPeerStateEventEmitter_Emit covers the two transitions this emitter
// surfaces (entering/leaving Established) and the two it must not
// (never-Established churn, and an address with no matching BGPPeer).
func TestPeerStateEventEmitter_Emit(t *testing.T) {
	router, peer := testRouterAndPeer()
	routerKey := types.NamespacedName{Namespace: router.Namespace, Name: router.Name}

	tests := []struct {
		name       string
		change     model.PeerStateChange
		wantEvent  bool
		wantType   string
		wantReason string
		wantMsg    string
	}{
		{
			name: "entering Established emits Normal/SessionEstablished",
			change: model.PeerStateChange{
				RouterKey: routerKey, Address: testEmitterPeerAddr, PeerASN: 65010,
				From: model.BGPPeerStateOpenConfirm, To: model.BGPPeerStateEstablished,
			},
			wantEvent: true, wantType: "Normal", wantReason: ReasonSessionEstablished,
			wantMsg: "transitioned to Established",
		},
		{
			name: "leaving Established emits Warning/SessionDown with disconnect detail",
			change: model.PeerStateChange{
				RouterKey: routerKey, Address: testEmitterPeerAddr, PeerASN: 65010,
				From: model.BGPPeerStateEstablished, To: model.BGPPeerStateIdle,
				DisconnectMessage: "hold timer expired",
			},
			wantEvent: true, wantType: "Warning", wantReason: ReasonSessionDown,
			wantMsg: "hold timer expired",
		},
		{
			name: "never-Established churn is not surfaced",
			change: model.PeerStateChange{
				RouterKey: routerKey, Address: testEmitterPeerAddr, PeerASN: 65010,
				From: model.BGPPeerStateIdle, To: model.BGPPeerStateConnect,
			},
			wantEvent: false,
		},
		{
			name: "no matching BGPPeer for the address",
			change: model.PeerStateChange{
				RouterKey: routerKey, Address: "2001:db8::dead",
				From: model.BGPPeerStateOpenConfirm, To: model.BGPPeerStateEstablished,
			},
			wantEvent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := events.NewFakeRecorder(1)
			emitter := NewPeerStateEventEmitter(newPeerEventsTestClient(t, router, peer), recorder)

			emitter.emit(context.Background(), tt.change)

			got := readFakeEvent(t, recorder)
			if !tt.wantEvent {
				if got != "" {
					t.Fatalf("expected no event, got: %s", got)
				}
				return
			}
			if got == "" {
				t.Fatal("expected an event, got none")
			}
			hasType := strings.Contains(got, tt.wantType)
			hasReason := strings.Contains(got, tt.wantReason)
			hasMsg := strings.Contains(got, tt.wantMsg)
			if !hasType || !hasReason || !hasMsg {
				t.Errorf("event = %q, want it to contain type %q, reason %q, message substring %q",
					got, tt.wantType, tt.wantReason, tt.wantMsg)
			}
		})
	}
}

// TestPeerStateEventEmitter_ObserveAndStart covers the full pipeline:
// ObservePeerStateChange enqueues, and Start's worker loop drains the queue
// and raises the Event, without the caller (the GoBGP watch goroutine, in
// production) ever blocking.
func TestPeerStateEventEmitter_ObserveAndStart(t *testing.T) {
	router, peer := testRouterAndPeer()
	recorder := events.NewFakeRecorder(1)
	emitter := NewPeerStateEventEmitter(newPeerEventsTestClient(t, router, peer), recorder)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- emitter.Start(ctx) }()

	emitter.ObservePeerStateChange(model.PeerStateChange{
		RouterKey: types.NamespacedName{Namespace: router.Namespace, Name: router.Name},
		Address:   testEmitterPeerAddr, PeerASN: 65010,
		From: model.BGPPeerStateOpenConfirm, To: model.BGPPeerStateEstablished,
	})

	if got := readFakeEvent(t, recorder); !strings.Contains(got, ReasonSessionEstablished) {
		t.Fatalf("event = %q, want it to contain %s", got, ReasonSessionEstablished)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Start() error = %v, want nil on context cancellation", err)
	}
}

// TestPeerStateEventDetails covers peerStateEventDetails' transition policy
// directly, independent of BGPPeer resolution.
func TestPeerStateEventDetails(t *testing.T) {
	tests := []struct {
		name       string
		change     model.PeerStateChange
		wantOK     bool
		wantType   string
		wantReason string
	}{
		{
			name:   "entering Established",
			change: model.PeerStateChange{From: model.BGPPeerStateActive, To: model.BGPPeerStateEstablished},
			wantOK: true, wantType: "Normal", wantReason: ReasonSessionEstablished,
		},
		{
			name:   "leaving Established",
			change: model.PeerStateChange{From: model.BGPPeerStateEstablished, To: model.BGPPeerStateActive},
			wantOK: true, wantType: "Warning", wantReason: ReasonSessionDown,
		},
		{
			name:   "never-Established churn is skipped",
			change: model.PeerStateChange{From: model.BGPPeerStateIdle, To: model.BGPPeerStateActive},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventType, reason, _, ok := peerStateEventDetails(tt.change)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if eventType != tt.wantType || reason != tt.wantReason {
				t.Errorf("got (%q, %q), want (%q, %q)", eventType, reason, tt.wantType, tt.wantReason)
			}
		})
	}
}
