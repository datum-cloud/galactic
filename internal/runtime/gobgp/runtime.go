// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v4/pkg/server"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/runtime"
)

// GoBGPRuntime implements runtime.RouterRuntime using an embedded GoBGP process.
type GoBGPRuntime struct {
	key          types.NamespacedName
	server       *Server
	listenPort   int32
	localAddress string
	mu           sync.Mutex

	lastASN      int64
	lastRouterID string
	// establishedAt tracks when each peer last reached the Established state.
	establishedAt map[string]time.Time
	// appliedPolicies tracks the direction of each applied policy by name so
	// stale policies can be removed when they disappear from desired state.
	appliedPolicies map[string]model.BGPPolicyDirection
	// appliedVRFs tracks the names of VRFs that have been applied to GoBGP so
	// stale VRFs can be removed when they disappear from desired state.
	appliedVRFs map[string]struct{}
	// serverCtxCancel cancels the goroutine running server.Start.
	serverCtxCancel context.CancelFunc
}

// NewRuntimeFactory returns a RuntimeFactory that creates a GoBGPRuntime per key.
// listenPort controls the TCP port GoBGP binds for incoming BGP connections.
// Pass -1 to disable inbound connections (outbound-only mode).
// localAddress, if non-empty, is bound as the source address for outgoing BGP
// TCP connections (sets Transport.LocalAddress on every peer).
func NewRuntimeFactory(listenPort int32, localAddress string) runtime.RuntimeFactory {
	return func(key types.NamespacedName) (runtime.RouterRuntime, error) {
		return &GoBGPRuntime{
			key:             key,
			server:          newServer(Config{}),
			listenPort:      listenPort,
			localAddress:    localAddress,
			establishedAt:   make(map[string]time.Time),
			appliedPolicies: make(map[string]model.BGPPolicyDirection),
			appliedVRFs:     make(map[string]struct{}),
		}, nil
	}
}

// Apply converges the running GoBGP instance toward desired.
func (r *GoBGPRuntime) Apply(ctx context.Context, desired model.DesiredRouter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := r.startGoBGP(ctx)
	if err != nil {
		return err
	}

	if err := r.applyGlobal(ctx, b, desired); err != nil {
		return err
	}

	if err := r.applyPeers(ctx, b, desired.Peers); err != nil {
		return err
	}

	if err := r.applyVRF(ctx, b, desired.VRFInstance); err != nil {
		return err
	}

	if err := r.applyEVPN(b, desired.Advertisements, desired.RouterID); err != nil {
		return err
	}

	if err := r.applyPolicies(ctx, b, desired.Policies); err != nil {
		return err
	}

	return nil
}

// startGoBGP boots the GoBGP server if it isn't already running.
func (r *GoBGPRuntime) startGoBGP(ctx context.Context) (*gobgpserver.BgpServer, error) {
	b := r.server.bgp.Load()
	if b == nil {
		srvCtx, cancel := context.WithCancel(context.Background())
		r.serverCtxCancel = cancel
		go func() {
			_ = r.server.Start(srvCtx)
		}()

		waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
		defer waitCancel()
		if err := r.server.WaitReady(waitCtx); err != nil {
			return nil, fmt.Errorf("gobgp not ready: %w", err)
		}
		b = r.server.bgp.Load()
	}

	return b, nil
}

// applyGlobal starts or reconfigures the BGP global instance and persists
// the last-seen ASN/RouterID so future changes can be detected.
func (r *GoBGPRuntime) applyGlobal(ctx context.Context, b *gobgpserver.BgpServer, desired model.DesiredRouter) error {
	asnChanged := r.lastASN != 0 && r.lastASN != desired.LocalASN
	idChanged := r.lastRouterID != "" && r.lastRouterID != desired.RouterID
	if asnChanged || idChanged {
		var recErr error
		b, recErr = r.server.Reconfigure()
		if recErr != nil {
			return fmt.Errorf("reconfigure gobgp: %w", recErr)
		}
	}

	resp, err := b.GetBgp(ctx, &api.GetBgpRequest{})
	needsStart := err != nil || resp == nil || resp.Global == nil || resp.Global.Asn == 0
	if needsStart {
		global := &api.Global{
			Asn:        uint32(desired.LocalASN),
			RouterId:   desired.RouterID,
			ListenPort: r.listenPort,
		}
		for _, af := range desired.AddressFamilies {
			global.Families = append(global.Families, familyToGlobalInt(af))
		}
		if err := b.StartBgp(ctx, &api.StartBgpRequest{Global: global}); err != nil {
			return fmt.Errorf("start bgp: %w", err)
		}
	}
	r.lastASN = desired.LocalASN
	r.lastRouterID = desired.RouterID
	return nil
}

// applyPeers adds, updates, and removes BGP peers to match desired state.
func (r *GoBGPRuntime) applyPeers(ctx context.Context, b *gobgpserver.BgpServer, peers []model.DesiredPeer) error {
	desiredPeers := make(map[string]model.DesiredPeer, len(peers))
	for _, p := range peers {
		desiredPeers[p.Address] = p
	}

	currentPeers := make(map[string]bool)
	if listErr := b.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		if p.Conf != nil {
			currentPeers[p.Conf.NeighborAddress] = true
		}
	}); listErr != nil {
		return fmt.Errorf("list peers: %w", listErr)
	}

	for _, p := range peers {
		peer := peerFromDesired(p, r.localAddress)
		addErr := b.AddPeer(ctx, &api.AddPeerRequest{Peer: peer})
		if addErr != nil {
			if strings.Contains(addErr.Error(), "can't overwrite") {
				if _, updateErr := b.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: peer}); updateErr != nil {
					return fmt.Errorf("update peer %s: %w", p.Address, updateErr)
				}
			} else {
				return fmt.Errorf("add peer %s: %w", p.Address, addErr)
			}
		}
	}

	for addr := range currentPeers {
		if _, ok := desiredPeers[addr]; !ok {
			_ = b.DeletePeer(ctx, &api.DeletePeerRequest{Address: addr})
		}
	}
	return nil
}

// applyVRF configures the desired VRF instance and removes stale ones.
func (r *GoBGPRuntime) applyVRF(ctx context.Context, b *gobgpserver.BgpServer, vrf *model.DesiredVRFInstance) error {
	if vrf != nil {
		if err := applyVRF(ctx, b, vrf); err != nil {
			return fmt.Errorf("apply VRF %s: %w", vrf.Name, err)
		}
		r.appliedVRFs[vrf.Name] = struct{}{}
	} else {
		delete(r.appliedVRFs, "")
	}

	for name := range r.appliedVRFs {
		if vrf == nil || vrf.Name != name {
			deleteVRF(ctx, b, name)
			delete(r.appliedVRFs, name)
		}
	}
	return nil
}

// applyEVPN advertises EVPN paths for all relevant advertisements.
func (r *GoBGPRuntime) applyEVPN(b *gobgpserver.BgpServer, advs []model.DesiredAdvertisement, routerID string) error {
	for _, adv := range advs {
		if adv.AddressFamily.AFI == afiL2VPN {
			if err := buildEVPNPaths(b, adv, routerID, false); err != nil {
				return fmt.Errorf("advertise EVPN paths for %s: %w", adv.Name, err)
			}
		}
	}
	return nil
}

// applyPolicies adds, updates, and removes BGP policies to match desired state.
func (r *GoBGPRuntime) applyPolicies(ctx context.Context, b *gobgpserver.BgpServer, policies []model.DesiredPolicy) error {
	desiredPolicies := make(map[string]model.BGPPolicyDirection, len(policies))
	for _, policy := range policies {
		desiredPolicies[policy.Name] = policy.Direction
		if err := applyPolicy(ctx, b, policy); err != nil {
			return fmt.Errorf("apply policy %q: %w", policy.Name, err)
		}
	}
	for name, direction := range r.appliedPolicies {
		if _, ok := desiredPolicies[name]; !ok {
			deletePolicy(ctx, b, name, direction)
		}
	}
	r.appliedPolicies = desiredPolicies
	return nil
}

// Status returns the observed state of the GoBGP instance.
func (r *GoBGPRuntime) Status(ctx context.Context) (model.RuntimeStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	b := r.server.bgp.Load()
	if b == nil {
		return model.RuntimeStatus{Healthy: false}, nil
	}

	// Check if BGP has been started.
	resp, err := b.GetBgp(ctx, &api.GetBgpRequest{})
	if err != nil || resp == nil || resp.Global == nil || resp.Global.Asn == 0 {
		return model.RuntimeStatus{Healthy: false}, nil
	}

	status := model.RuntimeStatus{Healthy: true}

	// Collect peer statuses.
	if listErr := b.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		if p.Conf == nil {
			return
		}
		ps := model.PeerStatus{
			Address: p.Conf.NeighborAddress,
			Name:    p.Conf.NeighborAddress,
		}
		if p.State != nil {
			ps.SessionState = fsmStateToModel(p.State.SessionState)
		}
		// Default to Idle if State is nil (e.g., incomplete peer config).
		if ps.SessionState == "" {
			ps.SessionState = model.BGPPeerStateIdle
		}
		if ps.SessionState == model.BGPPeerStateEstablished {
			if t, ok := r.establishedAt[p.Conf.NeighborAddress]; ok {
				mt := metav1.NewTime(t)
				ps.LastEstablishedTime = &mt
			} else {
				// First time we observe Established; record the time.
				now := time.Now()
				r.establishedAt[p.Conf.NeighborAddress] = now
				mt := metav1.NewTime(now)
				ps.LastEstablishedTime = &mt
			}
		}
		status.Peers = append(status.Peers, ps)
	}); listErr != nil {
		return model.RuntimeStatus{Healthy: false}, fmt.Errorf("list peers: %w", listErr)
	}

	return status, nil
}

// Stop shuts down the GoBGP server.
func (r *GoBGPRuntime) Stop(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.serverCtxCancel != nil {
		r.serverCtxCancel()
		r.serverCtxCancel = nil
	}
	return nil
}

// fsmStateToModel converts a GoBGP FSM state to a model.BGPPeerState.
func fsmStateToModel(state api.PeerState_SessionState) model.BGPPeerState {
	switch state {
	case api.PeerState_SESSION_STATE_IDLE:
		return model.BGPPeerStateIdle
	case api.PeerState_SESSION_STATE_CONNECT:
		return model.BGPPeerStateConnect
	case api.PeerState_SESSION_STATE_ACTIVE:
		return model.BGPPeerStateActive
	case api.PeerState_SESSION_STATE_OPENSENT:
		return model.BGPPeerStateOpenSent
	case api.PeerState_SESSION_STATE_OPENCONFIRM:
		return model.BGPPeerStateOpenConfirm
	case api.PeerState_SESSION_STATE_ESTABLISHED:
		return model.BGPPeerStateEstablished
	default:
		return model.BGPPeerStateIdle
	}
}

// applyVRF configures a VRF in GoBGP via AddVrf.
func applyVRF(ctx context.Context, b *gobgpserver.BgpServer, vrf *model.DesiredVRFInstance) error {
	// Parse the route distinguisher.
	rd, err := bgp.ParseRouteDistinguisher(vrf.RouteDistinguisher)
	if err != nil {
		return fmt.Errorf("parse route distinguisher %q: %w", vrf.RouteDistinguisher, err)
	}
	apiRD, err := apiutil.MarshalRD(rd)
	if err != nil {
		return fmt.Errorf("marshal route distinguisher %q: %w", vrf.RouteDistinguisher, err)
	}

	// Parse import route targets.
	importRTs, err := parseRouteTargetsToAPI(vrf.ImportRouteTargets)
	if err != nil {
		return fmt.Errorf("parse import route targets: %w", err)
	}

	// Parse export route targets.
	exportRTs, err := parseRouteTargetsToAPI(vrf.ExportRouteTargets)
	if err != nil {
		return fmt.Errorf("parse export route targets: %w", err)
	}

	return b.AddVrf(ctx, &api.AddVrfRequest{
		Vrf: &api.Vrf{
			Name:     vrf.Name,
			Rd:       apiRD,
			ImportRt: importRTs,
			ExportRt: exportRTs,
		},
	})
}

// deleteVRF removes a VRF from GoBGP.
func deleteVRF(ctx context.Context, b *gobgpserver.BgpServer, name string) {
	_ = b.DeleteVrf(ctx, &api.DeleteVrfRequest{Name: name})
}

// parseRouteTargetsToAPI parses route target strings into GoBGP API RouteTarget objects.
func parseRouteTargetsToAPI(targets []string) ([]*api.RouteTarget, error) {
	apiRTs := make([]*api.RouteTarget, 0, len(targets))
	for _, t := range targets {
		rt, err := bgp.ParseRouteTarget(t)
		if err != nil {
			return nil, fmt.Errorf("invalid route target %q: %w", t, err)
		}
		apiRT, err := apiutil.MarshalRT(rt)
		if err != nil {
			return nil, fmt.Errorf("marshal route target %q: %w", t, err)
		}
		apiRTs = append(apiRTs, apiRT)
	}
	return apiRTs, nil
}
