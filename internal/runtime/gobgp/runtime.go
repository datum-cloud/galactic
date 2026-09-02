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
	key    types.NamespacedName
	server *Server
	// listenPort is the process-wide default TCP port GoBGP binds for
	// incoming BGP connections (from GALACTIC_ROUTER_BGP_LISTEN_PORT). A
	// per-router BGPRouter.spec.listenPort, carried as DesiredRouter.ListenPort,
	// overrides it when set — see applyGlobal.
	listenPort   int32
	reflector    bool
	localAddress string
	mu           sync.Mutex

	lastASN      int64
	lastRouterID string
	// lastListenPort is the effective listen port (r.listenPort, overridden by
	// DesiredRouter.ListenPort when set) applied on the last StartBgp — zero
	// means "not yet applied," the same unset-sentinel convention lastASN and
	// lastRouterID use, since a real listen port is never 0 (validated to
	// -1 or 1-65535 upstream). A change forces a Reconfigure, same as
	// asnChanged/idChanged, because GoBGP cannot rebind its listen socket on
	// an already-started BgpServer.
	lastListenPort int32
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
	// appliedVRFImportRTs tracks the last-applied import route-target set for
	// each already-registered VRF, keyed by VRF name, so applyVRFs can detect
	// when an existing VRF's import RTs change (not just when a VRF is first
	// registered) and trigger a RIB backfill for it — see applyVRFs.
	appliedVRFImportRTs map[string][]string
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
	// peerMonitorOnce ensures the shared peer FSM transition watcher goroutine
	// (see peer_monitor.go) is started at most once per runtime lifetime, the
	// same one-shared-goroutine pattern monitorOnce uses for EVPN best-path.
	peerMonitorOnce sync.Once
	// peerStateMu guards lastPeerState. Kept separate from mu (rather than
	// reusing it) so the peer-event watcher goroutine — which fires
	// concurrently with Apply/Status — never contends with the lock those
	// hold for potentially long VRF/policy convergence work.
	peerStateMu sync.Mutex
	// lastPeerState tracks each peer's last-observed FSM state, keyed by
	// neighbor address, so onPeerUpdate can detect an actual transition
	// instead of logging every re-signal of the same state. This is distinct
	// from establishedAt below: that one records when a peer first reached
	// Established for status reporting, this one records the current state
	// of every peer regardless of what it is, for transition logging.
	lastPeerState map[string]model.BGPPeerState
	// appliedPeers tracks the last-applied DesiredPeer per address so
	// applyPeers can skip re-adding/updating a peer whose config hasn't
	// actually changed. Without this, applyPeers called AddPeer/UpdatePeer
	// for every desired peer on every Apply() — including reconciles where
	// nothing changed — and GoBGP's UpdatePeer resets the session
	// unconditionally, so a peer could never stay Established: any
	// watch-triggered reconcile (including one caused by this router's own
	// BGPPeer status write) tore every session back down before it converged.
	appliedPeers map[string]model.DesiredPeer
	// observer, when non-nil, is notified in real time of every peer FSM
	// transition onPeerUpdate detects (see peer_monitor.go). May be nil in
	// tests that construct a GoBGPRuntime directly without going through
	// NewRuntimeFactory.
	observer model.PeerStateObserver
	// wg tracks the server.Start and watchEVPNRIB goroutines so Stop can block
	// until both have actually exited instead of merely cancelling srvCtx and
	// returning. GoBGP keeps some path-selection state (table.SelectionOptions,
	// table.UseMultiplePaths) as package-level globals rather than per-server
	// fields, so a BgpServer that outlives Stop() races the next runtime's
	// StartBgp in any test (or other in-process caller) that creates more than
	// one GoBGPRuntime -- this is what the CI race detector caught once this
	// package's tests started creating more than one GoBGPRuntime per run.
	wg sync.WaitGroup
}

// NewRuntimeFactory returns a RuntimeFactory that creates a GoBGPRuntime per key.
// listenPort controls the TCP port GoBGP binds for incoming BGP connections.
// Pass -1 to disable inbound connections (outbound-only mode).
// reflector, when true, marks every peer of this runtime instance as an iBGP
// route-reflector client — this is a distinct, explicit signal from
// listenPort: whether a node accepts inbound BGP is not the same property as
// whether it is the fabric-facing route-reflector, even though the two
// happen to coincide in every overlay that exists today.
// localAddress, if non-empty, is bound as the source address for outgoing BGP
// TCP connections (sets Transport.LocalAddress on every peer).
// observer, when non-nil, is notified in real time of every peer FSM
// transition each created runtime detects (see peer_monitor.go); pass nil to
// disable this (e.g. in tests that don't care about it).
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

// peerNeedsApply reports whether p must be (re-)pushed to GoBGP via
// AddPeer/UpdatePeer: either it was never applied, its desired config
// changed since the last apply, or GoBGP no longer reports it as configured
// (e.g. silently dropped by an unrelated churn elsewhere, such as a GC cycle
// recreating the BGPVRFInstance/BGPAdvertisement CRs backing it). Any other
// case is a true no-op — skipping it matters because AddPeer/UpdatePeer
// reset the BGP session unconditionally, even when the pushed config is
// identical to what's already running.
func peerNeedsApply(applied map[string]model.DesiredPeer, current map[string]bool, p model.DesiredPeer) bool {
	last, ok := applied[p.Address]
	return !ok || !current[p.Address] || !reflect.DeepEqual(last, p)
}

// applyVRFs configures every desired VRF instance and removes stale ones. A
// node can host many VRFs (one per VPC that has at least one attachment on
// this node, shared by every attachment on that VPC/node — not one per
// attachment), so this — unlike the single-VRF code it replaces — must
// handle the full set, not just one.
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
			// This VRF was already registered, but its import route-target
			// set has changed (e.g. an import policy widened to pick up
			// another VPC/location's RT). A remote path matching a
			// newly-added RT may already be best-path in GoBGP's RIB —
			// added before this VRF's rtIndex entry existed for that RT —
			// and watchEVPNRIB only notifies on *future* best-path events,
			// so it would never be redelivered without a backfill.
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

	// A newly registered VRF's route targets, or a route-target set that
	// changed on an already-registered VRF, may match paths that were
	// already best-path in GoBGP's RIB before that RT existed in rtIndex —
	// the shared watcher's WatchBestPath(true) only replays the RIB once, at
	// its own startup, so it would never redeliver those. Backfill from the
	// current RIB now that rtIndex reflects the change.
	if needsBackfill {
		r.backfillEVPNRoutes(b)
	}

	return nil
}

// equalRTSets reports whether a and b contain the same route targets,
// ignoring order — the desired route-target list's order isn't guaranteed
// stable across reconciles, since it round-trips through a Kubernetes CR
// spec (BGPVRFInstance.Spec.ImportRouteTargets).
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

// Stop shuts down the GoBGP server. It blocks until the embedded server and
// the shared EVPN RIB watcher have both actually exited (not merely been
// asked to), so a caller that creates another GoBGPRuntime immediately after
// Stop returns -- as tests in this package do -- cannot race the outgoing
// server's GoBGP package-level path-selection state (see the wg field doc).
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

// applyVRF configures a VRF in GoBGP via AddVrf. The route distinguisher is
// derived as the RFC 4364 Type 1 (IP-address:local-admin) format
// "routerID:vrfID", matching the convention buildEVPNPaths uses for the
// per-VRF RD so that EVPN paths and VRF registration share the same distinguisher.
// If the VRF already exists, the call is treated as idempotent (no-op).
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
