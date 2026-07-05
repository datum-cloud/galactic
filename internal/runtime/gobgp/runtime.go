// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
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
	// appliedVRFs tracks the kernel VRF table ID of each VRF that has been
	// applied to GoBGP, keyed by VRF name, so stale VRFs can be removed when
	// they disappear from desired state and so the route-write privilege probe
	// runs only once per VRF rather than on every reconcile.
	appliedVRFs map[string]uint32
	// rtIndexMu guards rtIndex, which is read concurrently by the shared EVPN
	// RIB watcher goroutine.
	rtIndexMu sync.RWMutex
	// rtIndex maps an import route-target string to the kernel VRF table ID
	// that imports it, letting the single shared watcher dispatch a best-path
	// event to the right table in O(1) instead of scanning every VRF — a node
	// can host thousands of VPC attachments, each with its own VRF.
	rtIndex map[string]uint32
	// appliedAdvertisements tracks the last-applied DesiredAdvertisement per
	// name so a changed advertisement's previous EVPN paths can be withdrawn.
	// This matters because the EVPN Type 5 route's Gateway IP Address (the
	// SRv6 SID) is part of the NLRI itself, not a mutable path attribute:
	// re-adding a path with a new SID creates a structurally different route
	// rather than replacing the old one, so the stale route must be withdrawn
	// explicitly or it stays advertised indefinitely.
	appliedAdvertisements map[string]model.DesiredAdvertisement
	// serverCtxCancel cancels the goroutine running server.Start.
	serverCtxCancel context.CancelFunc
	// srvCtx is the context passed to server.Start; monitor goroutines use it.
	srvCtx context.Context
	// monitorOnce ensures the single shared EVPN RIB watcher goroutine is
	// started at most once per runtime lifetime; it dispatches to all VRFs via
	// rtIndex rather than being scoped to one VRF.
	monitorOnce sync.Once
}

// NewRuntimeFactory returns a RuntimeFactory that creates a GoBGPRuntime per key.
// listenPort controls the TCP port GoBGP binds for incoming BGP connections.
// Pass -1 to disable inbound connections (outbound-only mode).
// localAddress, if non-empty, is bound as the source address for outgoing BGP
// TCP connections (sets Transport.LocalAddress on every peer).
func NewRuntimeFactory(listenPort int32, localAddress string) runtime.RuntimeFactory {
	return func(key types.NamespacedName) (runtime.RouterRuntime, error) {
		return &GoBGPRuntime{
			key:                   key,
			server:                newServer(Config{}),
			listenPort:            listenPort,
			localAddress:          localAddress,
			establishedAt:         make(map[string]time.Time),
			appliedPolicies:       make(map[string]model.BGPPolicyDirection),
			appliedVRFs:           make(map[string]uint32),
			rtIndex:               make(map[string]uint32),
			appliedAdvertisements: make(map[string]model.DesiredAdvertisement),
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

	if err := r.applyVRFs(ctx, b, desired.VRFInstances); err != nil {
		return err
	}

	r.startRIBMonitor(b)

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
		r.srvCtx = srvCtx
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
		peer := peerFromDesired(p, r.localAddress, r.listenPort > 0)
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

// applyVRFs configures every desired VRF instance and removes stale ones. A
// node can host thousands of VRFs (one per VPC attachment), so this — unlike
// the single-VRF code it replaces — must handle the full set, not just one.
func (r *GoBGPRuntime) applyVRFs(ctx context.Context, b *gobgpserver.BgpServer, vrfs []model.DesiredVRFInstance) error {
	desired := make(map[string]model.DesiredVRFInstance, len(vrfs))
	for _, v := range vrfs {
		desired[v.Name] = v
	}
	for name := range r.appliedVRFs {
		if _, ok := desired[name]; !ok {
			deleteVRF(ctx, b, name)
			delete(r.appliedVRFs, name)
		}
	}

	rtIndex := make(map[string]uint32, len(vrfs))
	newlyRegistered := false
	for _, v := range vrfs {
		if err := applyVRF(ctx, b, &v); err != nil {
			return fmt.Errorf("apply VRF %s: %w", v.Name, err)
		}

		tableID, ok := r.appliedVRFs[v.Name]
		if !ok {
			var err error
			tableID, err = vrfTableID(v.Name)
			if err != nil {
				slog.Error("applyVRFs: failed to resolve kernel VRF table; SEG6 encap routes will not be installed",
					"vrf", v.Name, "err", err)
				continue
			}
			if err := probeRouteWrite(tableID); err != nil {
				slog.Error("applyVRFs: route write probe failed; SEG6 encap routes will not be installed",
					"vrf", v.Name, "err", err,
					"hint", "set runAsUser: 0 and capabilities.add: [NET_ADMIN] in the container securityContext")
				continue
			}
			r.appliedVRFs[v.Name] = tableID
			newlyRegistered = true
		}
		for _, rt := range v.ImportRouteTargets {
			rtIndex[rt] = tableID
		}
	}

	r.rtIndexMu.Lock()
	r.rtIndex = rtIndex
	r.rtIndexMu.Unlock()

	// A newly registered VRF's route targets may match paths that were
	// already best-path in GoBGP's RIB before this VRF existed in rtIndex —
	// the shared watcher's WatchBestPath(true) only replays the RIB once, at
	// its own startup, so it would never redeliver those. Backfill from the
	// current RIB now that rtIndex includes the new VRF.
	if newlyRegistered {
		r.backfillEVPNRoutes(b)
	}

	return nil
}

// applyEVPN advertises EVPN paths for all relevant advertisements, withdrawing
// each advertisement's previous paths first when its content has changed.
func (r *GoBGPRuntime) applyEVPN(b *gobgpserver.BgpServer, advs []model.DesiredAdvertisement, routerID string) error {
	desiredNames := make(map[string]struct{}, len(advs))
	for _, adv := range advs {
		if adv.AddressFamily.AFI != afiL2VPN {
			continue
		}
		desiredNames[adv.Name] = struct{}{}

		if oldAdv, ok := r.appliedAdvertisements[adv.Name]; ok {
			if reflect.DeepEqual(oldAdv, adv) {
				continue
			}
			if err := buildEVPNPaths(b, oldAdv, routerID, true); err != nil {
				return fmt.Errorf("withdraw stale EVPN paths for %s: %w", adv.Name, err)
			}
		}

		if err := buildEVPNPaths(b, adv, routerID, false); err != nil {
			return fmt.Errorf("advertise EVPN paths for %s: %w", adv.Name, err)
		}
		r.appliedAdvertisements[adv.Name] = adv
	}

	// Withdraw advertisements that no longer exist in desired state.
	for name, oldAdv := range r.appliedAdvertisements {
		if _, ok := desiredNames[name]; ok {
			continue
		}
		if err := buildEVPNPaths(b, oldAdv, routerID, true); err != nil {
			return fmt.Errorf("withdraw removed EVPN advertisement %s: %w", name, err)
		}
		delete(r.appliedAdvertisements, name)
	}
	return nil
}

// applyPolicies adds, updates, and removes BGP policies to match desired state.
func (r *GoBGPRuntime) applyPolicies(
	ctx context.Context, b *gobgpserver.BgpServer,
	policies []model.DesiredPolicy,
) error {
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
// If the VRF already exists, the call is treated as idempotent (no-op).
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

	err = b.AddVrf(ctx, &api.AddVrfRequest{
		Vrf: &api.Vrf{
			Name:     vrf.Name,
			Rd:       apiRD,
			ImportRt: importRTs,
			ExportRt: exportRTs,
		},
	})
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return nil // idempotent: VRF already configured
	}
	return err
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
