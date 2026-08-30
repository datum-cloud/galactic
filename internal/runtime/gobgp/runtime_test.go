// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

// newTestBgpServer starts a bare embedded GoBGP server suitable for exercising
// AddVrf/ListVrf in isolation, with no listening socket and no peers.
func newTestBgpServer(t *testing.T) *gobgpserver.BgpServer {
	t.Helper()
	b := gobgpserver.NewBgpServer()
	go b.Serve()
	t.Cleanup(b.Stop)

	if err := b.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65000,
			RouterId:   testRouterID1,
			ListenPort: -1,
		},
	}); err != nil {
		t.Fatalf("StartBgp() error = %v", err)
	}
	return b
}

// TestApplyGlobal_ListenPortOverride verifies DesiredRouter.ListenPort (carried
// from BGPRouter.spec.listenPort) overrides the runtime's process-wide default
// listen port (from GALACTIC_ROUTER_BGP_LISTEN_PORT / NewRuntimeFactory) when
// set — this is the wiring that was missing entirely before, leaving
// spec.listenPort a dead CRD field.
func TestApplyGlobal_ListenPortOverride(t *testing.T) {
	ctx := context.Background()

	// Factory default is -1 (outbound-only) -- e.g. the default per-node role.
	factory := NewRuntimeFactory(-1, false, "")
	rt, err := factory(types.NamespacedName{Namespace: "default", Name: "r1"})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Stop(ctx) })

	desired := model.DesiredRouter{
		LocalASN:   65000,
		RouterID:   testRouterID1,
		ListenPort: ptrInt32Test(1790),
	}
	if err := rt.Apply(ctx, desired); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	gr := rt.(*GoBGPRuntime)
	b := gr.server.bgp.Load()
	resp, err := b.GetBgp(ctx, &api.GetBgpRequest{})
	if err != nil {
		t.Fatalf("GetBgp() error = %v", err)
	}
	if resp.Global.ListenPort != 1790 {
		t.Errorf("Global.ListenPort = %d, want 1790 (CR override over factory default -1)", resp.Global.ListenPort)
	}
}

// TestApplyGlobal_ListenPortUnsetFallsBackToFactoryDefault verifies a
// DesiredRouter with ListenPort left nil (BGPRouter.spec.listenPort unset)
// falls back to the runtime's process-wide default, unchanged from before
// spec.listenPort existed.
func TestApplyGlobal_ListenPortUnsetFallsBackToFactoryDefault(t *testing.T) {
	ctx := context.Background()

	factory := NewRuntimeFactory(17901, false, "")
	rt, err := factory(types.NamespacedName{Namespace: "default", Name: "r1"})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Stop(ctx) })

	desired := model.DesiredRouter{
		LocalASN: 65000,
		RouterID: testRouterID1,
	}
	if err := rt.Apply(ctx, desired); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	gr := rt.(*GoBGPRuntime)
	b := gr.server.bgp.Load()
	resp, err := b.GetBgp(ctx, &api.GetBgpRequest{})
	if err != nil {
		t.Fatalf("GetBgp() error = %v", err)
	}
	if resp.Global.ListenPort != 17901 {
		t.Errorf("Global.ListenPort = %d, want 17901 (factory default, spec.listenPort unset)", resp.Global.ListenPort)
	}
}

// TestPeerNeedsApply guards the fix for a bug where applyPeers called
// AddPeer/UpdatePeer for every desired peer on every Apply(), including
// reconciles where nothing about the peer had changed. GoBGP's UpdatePeer
// resets the BGP session unconditionally, so that made every peer flap
// continuously under any watch-triggered reconcile storm (e.g. one caused by
// the router's own BGPPeer status write) — no session ever stayed
// Established. peerNeedsApply must say "skip" only when the peer's config is
// truly unchanged and GoBGP still reports it as configured.
func TestPeerNeedsApply(t *testing.T) {
	const addr = "2607:ed40:1ff::1"
	peer := model.DesiredPeer{
		Name:       "to-worker",
		PeerASN:    33438,
		Address:    addr,
		RemotePort: 1790,
		HoldTime:   30,
	}

	tests := []struct {
		name    string
		applied map[string]model.DesiredPeer
		current map[string]bool
		peer    model.DesiredPeer
		want    bool
	}{
		{
			name:    "never applied before",
			applied: map[string]model.DesiredPeer{},
			current: map[string]bool{},
			peer:    peer,
			want:    true,
		},
		{
			name:    "unchanged and still configured in GoBGP: skip",
			applied: map[string]model.DesiredPeer{addr: peer},
			current: map[string]bool{addr: true},
			peer:    peer,
			want:    false,
		},
		{
			name:    "config changed since last apply",
			applied: map[string]model.DesiredPeer{addr: peer},
			current: map[string]bool{addr: true},
			peer:    func() model.DesiredPeer { p := peer; p.HoldTime = 90; return p }(),
			want:    true,
		},
		{
			name:    "applied but silently dropped by GoBGP (e.g. unrelated GC churn)",
			applied: map[string]model.DesiredPeer{addr: peer},
			current: map[string]bool{},
			peer:    peer,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerNeedsApply(tt.applied, tt.current, tt.peer); got != tt.want {
				t.Errorf("peerNeedsApply() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestApplyVRFDerivesRouteDistinguisher verifies applyVRF derives the RFC 4364
// Type 1 route distinguisher as "routerID:vrfID" from the routerID parameter
// and vrf.VRFID, rather than reading a RouteDistinguisher field off the model
// (which no longer exists after the BGPVRFInstanceSpec.VRFID API change).
func TestApplyVRFDerivesRouteDistinguisher(t *testing.T) {
	tests := []struct {
		name     string
		routerID string
		vrf      model.DesiredVRFInstance
		wantRD   string
	}{
		{
			name:     "basic vrfID",
			routerID: testRouterID1,
			vrf: model.DesiredVRFInstance{
				Name:               "vrf-a",
				VRFID:              42,
				ImportRouteTargets: []string{"65000:100"},
				ExportRouteTargets: []string{"65000:100"},
			},
			wantRD: "1.2.3.4:42",
		},
		{
			name:     "different routerID and vrfID",
			routerID: "10.0.0.1",
			vrf: model.DesiredVRFInstance{
				Name:               "vrf-b",
				VRFID:              65535,
				ImportRouteTargets: []string{"65000:200"},
				ExportRouteTargets: []string{"65000:200"},
			},
			wantRD: "10.0.0.1:65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBgpServer(t)
			ctx := context.Background()

			vrf := tt.vrf
			if err := applyVRF(ctx, b, &vrf, tt.routerID); err != nil {
				t.Fatalf("applyVRF() error = %v", err)
			}

			var gotRD string
			if err := b.ListVrf(ctx, &api.ListVrfRequest{}, func(v *api.Vrf) {
				if v.Name != tt.vrf.Name {
					return
				}
				rd, err := apiutil.UnmarshalRD(v.Rd)
				if err != nil {
					t.Fatalf("UnmarshalRD() error = %v", err)
				}
				gotRD = rd.String()
			}); err != nil {
				t.Fatalf("ListVrf() error = %v", err)
			}

			if gotRD != tt.wantRD {
				t.Errorf("applyVRF() route distinguisher = %q, want %q", gotRD, tt.wantRD)
			}
		})
	}
}

// TestEqualRTSets verifies the order-independent route-target set comparison
// applyVRFs uses to detect when an already-registered VRF's import RTs
// change (e.g. an import policy widens to pick up another VPC/location's
// RT) — the signal that must trigger a RIB backfill so an already-best-path
// remote route isn't left undelivered until the next router restart.
func TestEqualRTSets(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{name: "both empty", a: nil, b: nil, want: true},
		{name: "identical single", a: []string{testRT100}, b: []string{testRT100}, want: true},
		{
			name: "same elements, different order",
			a:    []string{testRT100, testRT200},
			b:    []string{testRT200, testRT100},
			want: true,
		},
		{
			name: "widened set (RT added)",
			a:    []string{testRT100},
			b:    []string{testRT100, testRT200},
			want: false,
		},
		{
			name: "narrowed set (RT removed)",
			a:    []string{testRT100, testRT200},
			b:    []string{testRT100},
			want: false,
		},
		{
			name: "same length, disjoint",
			a:    []string{testRT100},
			b:    []string{testRT200},
			want: false,
		},
		{
			name: "duplicate handling",
			a:    []string{testRT100, testRT100},
			b:    []string{testRT100},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := equalRTSets(tt.a, tt.b); got != tt.want {
				t.Errorf("equalRTSets(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
			// Symmetric.
			if got := equalRTSets(tt.b, tt.a); got != tt.want {
				t.Errorf("equalRTSets(%v, %v) = %v, want %v (symmetry)", tt.b, tt.a, got, tt.want)
			}
		})
	}
}
