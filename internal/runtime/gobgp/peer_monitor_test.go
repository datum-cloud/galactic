// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

const (
	// testRouterName and testPeerAddr are shared across this file's test
	// cases purely as fixture values -- their meaning stops at "some name"
	// and "some address," so a single constant, rather than each test
	// spelling out the same literal, keeps golangci-lint's goconst happy
	// without the tests losing anything.
	testRouterName          = "router"
	testPeerAddr            = "2001:db8::1"
	testHoldTimerExpiredMsg = "hold timer expired"
)

func TestBGPFSMStateToModel(t *testing.T) {
	tests := []struct {
		name  string
		state bgp.FSMState
		want  model.BGPPeerState
	}{
		{name: "idle", state: bgp.BGP_FSM_IDLE, want: model.BGPPeerStateIdle},
		{name: "connect", state: bgp.BGP_FSM_CONNECT, want: model.BGPPeerStateConnect},
		{name: "active", state: bgp.BGP_FSM_ACTIVE, want: model.BGPPeerStateActive},
		{name: "opensent", state: bgp.BGP_FSM_OPENSENT, want: model.BGPPeerStateOpenSent},
		{name: "openconfirm", state: bgp.BGP_FSM_OPENCONFIRM, want: model.BGPPeerStateOpenConfirm},
		{name: "established", state: bgp.BGP_FSM_ESTABLISHED, want: model.BGPPeerStateEstablished},
		{name: "unknown falls back to idle", state: bgp.FSMState(99), want: model.BGPPeerStateIdle},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := bgpFSMStateToModel(tc.state); got != tc.want {
				t.Errorf("bgpFSMStateToModel(%v) = %v, want %v", tc.state, got, tc.want)
			}
		})
	}
}

// captureSlog swaps slog's default logger for one writing text output into
// the returned buffer, restoring the previous default when the test ends.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func peerEvent(t *testing.T, evType apiutil.PeerEventType, state bgp.FSMState) *apiutil.WatchEventMessage_PeerEvent {
	t.Helper()
	parsed, err := netip.ParseAddr(testPeerAddr)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%q): %v", testPeerAddr, err)
	}
	return &apiutil.WatchEventMessage_PeerEvent{
		Type: evType,
		Peer: apiutil.Peer{
			Conf: apiutil.PeerConf{
				PeerASN:         65001,
				NeighborAddress: parsed,
			},
			State: apiutil.PeerState{
				SessionState: state,
			},
		},
	}
}

// TestOnPeerUpdate_LogsFirstObservedTransition covers the base case: the
// first event seen for a peer is treated as a transition from Idle (the
// zero-value "not seen yet" state), and gets logged.
func TestOnPeerUpdate_LogsFirstObservedTransition(t *testing.T) {
	buf := captureSlog(t)
	r := &GoBGPRuntime{
		key:           types.NamespacedName{Namespace: "galactic-system", Name: testRouterName},
		lastPeerState: make(map[string]model.BGPPeerState),
	}

	r.onPeerUpdate(peerEvent(t, apiutil.PEER_EVENT_STATE, bgp.BGP_FSM_ACTIVE), time.Time{})

	out := buf.String()
	if !strings.Contains(out, "bgp peer state transition") {
		t.Fatalf("expected a transition log line, got: %s", out)
	}
	if !strings.Contains(out, "peer="+testPeerAddr) {
		t.Errorf("expected peer address in log line, got: %s", out)
	}
	if !strings.Contains(out, "from=Idle") || !strings.Contains(out, "to=Active") {
		t.Errorf("expected from=Idle to=Active in log line, got: %s", out)
	}
	if got := r.lastPeerState[testPeerAddr]; got != model.BGPPeerStateActive {
		t.Errorf("lastPeerState[peer] = %v, want Active", got)
	}
}

// TestOnPeerUpdate_SkipsRepeatOfSameState covers the dedup path: GoBGP can
// re-signal a state that hasn't actually changed, and that must not produce
// a duplicate log line.
func TestOnPeerUpdate_SkipsRepeatOfSameState(t *testing.T) {
	buf := captureSlog(t)
	r := &GoBGPRuntime{
		key:           types.NamespacedName{Name: testRouterName},
		lastPeerState: map[string]model.BGPPeerState{testPeerAddr: model.BGPPeerStateEstablished},
	}

	r.onPeerUpdate(peerEvent(t, apiutil.PEER_EVENT_STATE, bgp.BGP_FSM_ESTABLISHED), time.Time{})

	if buf.Len() != 0 {
		t.Errorf("expected no log line for a repeated state, got: %s", buf.String())
	}
}

// TestOnPeerUpdate_DownTransitionIncludesDisconnectReason covers the
// peer-down case: dropping out of Established must carry the
// DisconnectReason/DisconnectMessage GoBGP attaches to the event, since that
// is the whole point of logging a down transition (why it dropped, not just
// that it dropped).
func TestOnPeerUpdate_DownTransitionIncludesDisconnectReason(t *testing.T) {
	buf := captureSlog(t)
	r := &GoBGPRuntime{
		key:           types.NamespacedName{Name: testRouterName},
		lastPeerState: map[string]model.BGPPeerState{testPeerAddr: model.BGPPeerStateEstablished},
	}

	ev := peerEvent(t, apiutil.PEER_EVENT_STATE, bgp.BGP_FSM_IDLE)
	ev.Peer.State.DisconnectReason = api.PeerState_DISCONNECT_REASON_HOLD_TIMER_EXPIRED
	ev.Peer.State.DisconnectMessage = testHoldTimerExpiredMsg

	r.onPeerUpdate(ev, time.Time{})

	out := buf.String()
	if !strings.Contains(out, "from=Established") || !strings.Contains(out, "to=Idle") {
		t.Fatalf("expected from=Established to=Idle in log line, got: %s", out)
	}
	if !strings.Contains(out, "disconnectReason=") || !strings.Contains(out, testHoldTimerExpiredMsg) {
		t.Errorf("expected disconnect reason/message in down-transition log line, got: %s", out)
	}
}

// TestOnPeerUpdate_SkipsEndOfInit covers the PEER_EVENT_END_OF_INIT filter:
// that event marks the end of GoBGP's initial replay to a new watcher, not
// an FSM transition, and must not be logged or recorded.
func TestOnPeerUpdate_SkipsEndOfInit(t *testing.T) {
	buf := captureSlog(t)
	r := &GoBGPRuntime{
		key:           types.NamespacedName{Name: testRouterName},
		lastPeerState: make(map[string]model.BGPPeerState),
	}

	r.onPeerUpdate(peerEvent(t, apiutil.PEER_EVENT_END_OF_INIT, bgp.BGP_FSM_ESTABLISHED), time.Time{})

	if buf.Len() != 0 {
		t.Errorf("expected no log line for PEER_EVENT_END_OF_INIT, got: %s", buf.String())
	}
	if _, seen := r.lastPeerState[testPeerAddr]; seen {
		t.Errorf("expected lastPeerState to remain untouched by PEER_EVENT_END_OF_INIT")
	}
}

// spyObserver is a model.PeerStateObserver that records every call it
// receives, for asserting onPeerUpdate's observer-notification side effect.
type spyObserver struct {
	changes []model.PeerStateChange
}

func (s *spyObserver) ObservePeerStateChange(change model.PeerStateChange) {
	s.changes = append(s.changes, change)
}

// TestOnPeerUpdate_NotifiesObserver covers the real-time-events plumbing
// (docs/plans/router-bgp-peer-session-events.md): a real transition must
// reach r.observer with the same from/to/asn data the log line reports.
func TestOnPeerUpdate_NotifiesObserver(t *testing.T) {
	captureSlog(t)
	obs := &spyObserver{}
	r := &GoBGPRuntime{
		key:           types.NamespacedName{Namespace: "galactic-system", Name: testRouterName},
		lastPeerState: make(map[string]model.BGPPeerState),
		observer:      obs,
	}

	now := time.Now()
	r.onPeerUpdate(peerEvent(t, apiutil.PEER_EVENT_STATE, bgp.BGP_FSM_ACTIVE), now)

	if len(obs.changes) != 1 {
		t.Fatalf("observer got %d changes, want 1", len(obs.changes))
	}
	got := obs.changes[0]
	if got.RouterKey != r.key || got.Address != testPeerAddr || got.PeerASN != 65001 {
		t.Errorf("unexpected change identity: %+v", got)
	}
	if got.From != model.BGPPeerStateIdle || got.To != model.BGPPeerStateActive {
		t.Errorf("change = from %v to %v, want from Idle to Active", got.From, got.To)
	}
	if !got.Time.Equal(now) {
		t.Errorf("change.Time = %v, want %v", got.Time, now)
	}
}

// TestOnPeerUpdate_ObserverGetsDisconnectDetailOnlyLeavingEstablished covers
// two things: the observer receives disconnect detail on a down-transition,
// and does not on an up-transition (where GoBGP wouldn't set it anyway).
func TestOnPeerUpdate_ObserverGetsDisconnectDetailOnlyLeavingEstablished(t *testing.T) {
	captureSlog(t)
	obs := &spyObserver{}
	r := &GoBGPRuntime{
		key:           types.NamespacedName{Name: testRouterName},
		lastPeerState: map[string]model.BGPPeerState{testPeerAddr: model.BGPPeerStateEstablished},
		observer:      obs,
	}

	ev := peerEvent(t, apiutil.PEER_EVENT_STATE, bgp.BGP_FSM_IDLE)
	ev.Peer.State.DisconnectReason = api.PeerState_DISCONNECT_REASON_HOLD_TIMER_EXPIRED
	ev.Peer.State.DisconnectMessage = testHoldTimerExpiredMsg

	r.onPeerUpdate(ev, time.Time{})

	if len(obs.changes) != 1 {
		t.Fatalf("observer got %d changes, want 1", len(obs.changes))
	}
	got := obs.changes[0]
	if got.From != model.BGPPeerStateEstablished || got.To != model.BGPPeerStateIdle {
		t.Fatalf("change = from %v to %v, want from Established to Idle", got.From, got.To)
	}
	if got.DisconnectMessage != testHoldTimerExpiredMsg {
		t.Errorf("DisconnectMessage = %q, want %q", got.DisconnectMessage, testHoldTimerExpiredMsg)
	}
	if got.DisconnectReason == "" {
		t.Errorf("expected a non-empty DisconnectReason")
	}
}

// TestOnPeerUpdate_NilObserverDoesNotPanic covers the common case: most
// GoBGPRuntime instances in this package's other tests construct the struct
// directly without setting observer, so onPeerUpdate must tolerate a nil one.
func TestOnPeerUpdate_NilObserverDoesNotPanic(t *testing.T) {
	captureSlog(t)
	r := &GoBGPRuntime{
		key:           types.NamespacedName{Name: testRouterName},
		lastPeerState: make(map[string]model.BGPPeerState),
	}
	r.onPeerUpdate(peerEvent(t, apiutil.PEER_EVENT_STATE, bgp.BGP_FSM_ACTIVE), time.Time{})
}
