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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/runtime"
)

// GoBGPRuntime implements runtime.RouterRuntime using an embedded GoBGP process.
type GoBGPRuntime struct {
	key    types.NamespacedName
	server *Server
	mu     sync.Mutex

	lastASN      uint32
	lastRouterID string
	// establishedAt tracks when each peer last reached the Established state.
	establishedAt map[string]time.Time
	// appliedPolicies tracks the direction of each applied policy by name so
	// stale policies can be removed when they disappear from desired state.
	appliedPolicies map[string]model.BGPPolicyDirection
	// serverCtxCancel cancels the goroutine running server.Start.
	serverCtxCancel context.CancelFunc
}

// NewRuntimeFactory returns a RuntimeFactory that creates a GoBGPRuntime per key.
func NewRuntimeFactory() runtime.RuntimeFactory {
	return func(key types.NamespacedName) (runtime.RouterRuntime, error) {
		return &GoBGPRuntime{
			key:             key,
			server:          newServer(Config{}),
			establishedAt:   make(map[string]time.Time),
			appliedPolicies: make(map[string]model.BGPPolicyDirection),
		}, nil
	}
}

// Apply converges the running GoBGP instance toward desired.
func (r *GoBGPRuntime) Apply(ctx context.Context, desired model.DesiredRouter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Start GoBGP if not running. The check and store are both inside the
	// mutex to prevent two concurrent Apply calls from both seeing b==nil
	// and launching two Serve() loops.
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
			return fmt.Errorf("gobgp not ready: %w", err)
		}
		b = r.server.bgp.Load()
	}

	// Reconfigure if global parameters changed.
	asnChanged := r.lastASN != 0 && r.lastASN != desired.LocalASN
	idChanged := r.lastRouterID != "" && r.lastRouterID != desired.RouterID
	if asnChanged || idChanged {
		var recErr error
		b, recErr = r.server.Reconfigure()
		if recErr != nil {
			return fmt.Errorf("reconfigure gobgp: %w", recErr)
		}
	}

	// Apply global BGP config if not already started or after reconfigure.
	resp, err := b.GetBgp(ctx, &api.GetBgpRequest{})
	needsStart := err != nil || resp == nil || resp.Global == nil || resp.Global.Asn == 0
	if needsStart {
		global := &api.Global{
			Asn:        desired.LocalASN,
			RouterId:   desired.RouterID,
			ListenPort: -1,
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

	// Apply peers: build desired set, add/update, then remove stale ones.
	desiredPeers := make(map[string]model.DesiredPeer, len(desired.Peers))
	for _, p := range desired.Peers {
		desiredPeers[p.Address] = p
	}

	// Collect current peers.
	currentPeers := make(map[string]bool)
	if listErr := b.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		if p.Conf != nil {
			currentPeers[p.Conf.NeighborAddress] = true
		}
	}); listErr != nil {
		return fmt.Errorf("list peers: %w", listErr)
	}

	// Add or update desired peers.
	for _, p := range desired.Peers {
		peer := peerFromDesired(p)
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

	// Delete peers no longer in desired state.
	for addr := range currentPeers {
		if _, ok := desiredPeers[addr]; !ok {
			_ = b.DeletePeer(ctx, &api.DeletePeerRequest{Address: addr})
		}
	}

	// Apply advertisements. EVPN path construction is not yet implemented;
	// EVPN advertisements always fail and the controller sets Accepted=False.
	for _, adv := range desired.Advertisements {
		if adv.AddressFamily.AFI == afiL2VPN {
			if err := buildEVPNPath(adv, false); err != nil {
				// Return the error so the caller can set Accepted=False.
				return err
			}
		}
	}

	// Apply policies: add/update desired, remove stale.
	desiredPolicies := make(map[string]model.BGPPolicyDirection, len(desired.Policies))
	for _, policy := range desired.Policies {
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
