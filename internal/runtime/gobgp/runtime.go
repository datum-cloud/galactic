// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"errors"
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
	key    types.NamespacedName
	server *Server
	// listenPort is the process-wide default TCP port GoBGP binds for incoming
	// connections. A per-router listen port, carried on DesiredRouter,
	// overrides it when set.
	listenPort   int32
	reflector    bool
	localAddress string
	mu           sync.Mutex

	lastASN      int64
	lastRouterID string
	// lastListenPort is the effective listen port applied on the last start, 0
	// meaning not yet applied, since a real port is never 0. A change forces a
	// reconfigure, like an ASN or router ID change, because GoBGP cannot
	// rebind its listen socket on an already-started server.
	lastListenPort int32
	// establishedAt tracks when each peer last reached the Established state.
	establishedAt map[string]time.Time
	// appliedPolicies tracks the direction of each applied policy by name so
	// stale policies can be removed when they disappear from desired state.
	appliedPolicies map[string]model.BGPPolicyDirection
	// appliedVRFs tracks the kernel VRF table ID of each VRF applied to GoBGP,
	// keyed by VRF name, so stale VRFs can be removed when they leave desired
	// state and the route-write probe runs once per VRF rather than on every
	// reconcile.
	appliedVRFs map[string]uint32
	// appliedVRFImportRTs tracks the last-applied import route-target set per
	// registered VRF, so applyVRFs can tell when an existing VRF's targets
	// change, not only when a VRF is first registered, and trigger a RIB
	// backfill for it.
	appliedVRFImportRTs map[string][]string
	// rtIndexMu guards rtIndex, which is read concurrently by the shared EVPN
	// RIB watcher goroutine.
	rtIndexMu sync.RWMutex
	// rtIndex maps an import route target to the kernel VRF table ID importing
	// it, so the shared watcher dispatches a best-path event in constant time
	// rather than scanning every VRF. A node can host thousands.
	rtIndex map[string]uint32
	// appliedAdvertisements tracks the last-applied advertisement per name, so a
	// changed one's previous EVPN paths can be withdrawn. The route's gateway
	// address, the SRv6 SID, is part of the NLRI rather than a mutable
	// attribute, so re-adding a path with a new SID creates a structurally
	// different route instead of replacing the old one, which then stays
	// advertised until withdrawn explicitly.
	appliedAdvertisements map[string]model.DesiredAdvertisement
	// serverCtxCancel cancels the goroutine running server.Start.
	serverCtxCancel context.CancelFunc
	// srvCtx is the context passed to server.Start; monitor goroutines use it.
	srvCtx context.Context
	// monitorOnce starts the shared EVPN RIB watcher at most once per runtime
	// lifetime. It dispatches to every VRF through rtIndex rather than being
	// scoped to one.
	monitorOnce sync.Once
	// peerMonitorOnce starts the shared peer FSM watcher at most once per
	// runtime lifetime, as monitorOnce does for best-path events.
	peerMonitorOnce sync.Once
	// peerStateMu guards lastPeerState, kept separate from mu so the peer-event
	// watcher never contends with the lock Apply and Status hold for
	// potentially long VRF and policy convergence work.
	peerStateMu sync.Mutex
	// lastPeerState tracks each peer's last-observed FSM state, keyed by
	// neighbor address, so a transition can be told apart from a re-signal of
	// the same state. Distinct from establishedAt, which records when a peer
	// first reached Established for status reporting.
	lastPeerState map[string]model.BGPPeerState
	// appliedPeers tracks the last-applied peer config per address, so a peer
	// whose config has not changed is not pushed again. GoBGP resets the
	// session on every update, even an identical one, so without this any
	// reconcile, including one caused by this router's own status write, tore
	// every session down before it could converge.
	appliedPeers map[string]model.DesiredPeer
	// observer, when non-nil, is notified of every peer FSM transition
	// detected. It may be nil in tests that construct a runtime directly.
	observer model.PeerStateObserver
	// wg tracks the server and RIB watcher goroutines so Stop blocks until both
	// have exited rather than merely being asked to. GoBGP keeps some
	// path-selection state in package-level globals rather than per-server
	// fields, so a server that outlives Stop races the next runtime's start in
	// any process that creates more than one.
	wg sync.WaitGroup
}

// NewRuntimeFactory returns a RuntimeFactory that creates one GoBGPRuntime per
// key.
//
// listenPort is the TCP port GoBGP binds for incoming connections; -1 disables
// inbound connections entirely. reflector marks every peer of the created
// runtime as an iBGP route-reflector client. That is deliberately separate from
// listenPort: whether a node accepts inbound BGP is not the same property as
// whether it is the fabric's route reflector, even where the two coincide today.
// localAddress, when non-empty, is bound as the source address for outgoing BGP
// connections. observer, when non-nil, is notified of every peer FSM transition
// each created runtime detects.
func NewRuntimeFactory(
	listenPort int32, reflector bool, localAddress string, observer model.PeerStateObserver,
) runtime.RuntimeFactory {
	return func(key types.NamespacedName) (runtime.RouterRuntime, error) {
		return &GoBGPRuntime{
			key:                   key,
			server:                newServer(Config{}),
			listenPort:            listenPort,
			reflector:             reflector,
			localAddress:          localAddress,
			establishedAt:         make(map[string]time.Time),
			lastPeerState:         make(map[string]model.BGPPeerState),
			appliedPeers:          make(map[string]model.DesiredPeer),
			appliedPolicies:       make(map[string]model.BGPPolicyDirection),
			appliedVRFs:           make(map[string]uint32),
			appliedVRFImportRTs:   make(map[string][]string),
			rtIndex:               make(map[string]uint32),
			appliedAdvertisements: make(map[string]model.DesiredAdvertisement),
			observer:              observer,
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

	if err := r.applyVRFs(ctx, b, desired.VRFInstances, desired.RouterID); err != nil {
		return err
	}

	r.startRIBMonitor(b)
	r.startPeerMonitor(b)

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
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
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
// the last-seen ASN/RouterID/ListenPort so future changes can be detected.
func (r *GoBGPRuntime) applyGlobal(ctx context.Context, b *gobgpserver.BgpServer, desired model.DesiredRouter) error {
	listenPort := r.listenPort
	if desired.ListenPort != nil {
		listenPort = *desired.ListenPort
	}

	asnChanged := r.lastASN != 0 && r.lastASN != desired.LocalASN
	idChanged := r.lastRouterID != "" && r.lastRouterID != desired.RouterID
	listenPortChanged := r.lastListenPort != 0 && r.lastListenPort != listenPort
	if asnChanged || idChanged || listenPortChanged {
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
			ListenPort: listenPort,
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
	r.lastListenPort = listenPort
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
		if !peerNeedsApply(r.appliedPeers, currentPeers, p) {
			continue
		}

		peer := peerFromDesired(p, r.localAddress, r.reflector)
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
		r.appliedPeers[p.Address] = p
	}

	for addr := range currentPeers {
		if _, ok := desiredPeers[addr]; !ok {
			_ = b.DeletePeer(ctx, &api.DeletePeerRequest{Address: addr})
			delete(r.appliedPeers, addr)
		}
	}
	return nil
}

// peerNeedsApply reports whether p must be pushed to GoBGP: it was never
// applied, its config changed since the last apply, or GoBGP no longer reports
// it as configured, which can happen when unrelated churn drops it. Any other
// case is a true no-op, and skipping matters because adding or updating a peer
// resets the session unconditionally, even when the config is identical.
func peerNeedsApply(applied map[string]model.DesiredPeer, current map[string]bool, p model.DesiredPeer) bool {
	last, ok := applied[p.Address]
	return !ok || !current[p.Address] || !reflect.DeepEqual(last, p)
}

// applyVRFs configures every desired VRF instance and removes stale ones. A node
// can host many VRFs, one per VPC with at least one attachment here and shared
// by every attachment on that VPC, so this handles the full set rather than a
// single VRF.
func (r *GoBGPRuntime) applyVRFs(
	ctx context.Context, b *gobgpserver.BgpServer, vrfs []model.DesiredVRFInstance, routerID string,
) error {
	desired := make(map[string]model.DesiredVRFInstance, len(vrfs))
	for _, v := range vrfs {
		desired[v.Name] = v
	}
	for name := range r.appliedVRFs {
		if _, ok := desired[name]; !ok {
			deleteVRF(ctx, b, name)
			delete(r.appliedVRFs, name)
			delete(r.appliedVRFImportRTs, name)
		}
	}

	rtIndex := make(map[string]uint32, len(vrfs))
	needsBackfill := false
	for _, v := range vrfs {
		if err := applyVRF(ctx, b, &v, routerID); err != nil {
			return fmt.Errorf("apply VRF %s: %w", v.Name, err)
		}

		tableID, ok := r.appliedVRFs[v.Name]
		if !ok {
			var err error
			tableID, err = vrfTableID(v.Name)
			if err != nil {
				// A VRF whose interface is not in this process's namespace is
				// the ordinary case for a VPC served only by the ingress
				// sidecar on this node, and there is nothing for this process
				// to install for it either way. Skip quietly rather than
				// report a failure on every reconcile.
				if errors.Is(err, errVRFNotInThisNetns) {
					slog.Debug("applyVRFs: skipping VRF whose kernel interface is not in this netns",
						"vrf", v.Name, "err", err)
					continue
				}
				slog.Error("applyVRFs: failed to resolve kernel VRF table; this VRF's routes will not be installed",
					"vrf", v.Name, "err", err)
				continue
			}
			if err := probeEgressRouteWrite(tableID); err != nil {
				slog.Error("applyVRFs: egress_route_table write probe failed; this VRF's routes will not be installed",
					"vrf", v.Name, "err", err,
					"hint", "set runAsUser: 0 and capabilities.add: [BPF] in the container securityContext, "+
						"and mount bpffs at "+pinDir)
				continue
			}
			r.appliedVRFs[v.Name] = tableID
			needsBackfill = true
		} else if !equalRTSets(r.appliedVRFImportRTs[v.Name], v.ImportRouteTargets) {
			// This VRF is registered but its import route targets have
			// changed, for instance because a policy widened to pick up
			// another location's target. A remote path matching a newly
			// added target may already be best path, having arrived
			// before the index held that target, and the watcher notifies
			// only on future events, so it would never be redelivered.
			needsBackfill = true
		}
		r.appliedVRFImportRTs[v.Name] = append([]string(nil), v.ImportRouteTargets...)

		for _, rt := range v.ImportRouteTargets {
			rtIndex[rt] = tableID
		}
	}

	r.rtIndexMu.Lock()
	r.rtIndex = rtIndex
	r.rtIndexMu.Unlock()

	// A newly registered VRF's targets, or a changed set on an existing one, may
	// match paths that were already best path before the index held that
	// target. The shared watcher replays the RIB only once, at its own startup,
	// so backfill from the current RIB now that the index reflects the
	// change.
	if needsBackfill {
		r.backfillEVPNRoutes(b)
	}

	return nil
}

// equalRTSets reports whether a and b hold the same route targets, ignoring
// order, since the desired list round-trips through a CRD spec and its order is
// not stable across reconciles.
func equalRTSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, rt := range a {
		counts[rt]++
	}
	for _, rt := range b {
		counts[rt]--
		if counts[rt] < 0 {
			return false
		}
	}
	return true
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

	// Collect advertisement statuses from the applied advertisements map.
	for name, adv := range r.appliedAdvertisements {
		status.Advertisements = append(status.Advertisements, model.AdvertisementStatus{
			Name:               name,
			AdvertisedPrefixes: int32(len(adv.Prefixes)),
		})
	}

	return status, nil
}

// Stop shuts down the GoBGP server, blocking until the embedded server and the
// EVPN RIB watcher have both exited rather than merely been asked to. A caller
// that creates another runtime immediately after would otherwise race the
// outgoing server's package-level path-selection state; see the wg field.
func (r *GoBGPRuntime) Stop(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.serverCtxCancel != nil {
		r.serverCtxCancel()
		r.serverCtxCancel = nil
	}
	r.wg.Wait()
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

// applyVRF configures one VRF in GoBGP. The route distinguisher is the RFC 4364
// Type 1 "routerID:vrfID" form, matching what EVPN path construction uses, so
// paths and VRF registration share one distinguisher. A VRF that already exists
// is a no-op.
func applyVRF(ctx context.Context, b *gobgpserver.BgpServer, vrf *model.DesiredVRFInstance, routerID string) error {
	// Derive and parse the route distinguisher.
	rdStr := fmt.Sprintf("%s:%d", routerID, vrf.VRFID)
	rd, err := bgp.ParseRouteDistinguisher(rdStr)
	if err != nil {
		return fmt.Errorf("parse route distinguisher %q: %w", rdStr, err)
	}
	apiRD, err := apiutil.MarshalRD(rd)
	if err != nil {
		return fmt.Errorf("marshal route distinguisher %q: %w", rdStr, err)
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
