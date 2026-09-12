// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// routeState tracks one pod's route lifecycle, keyed by its EndpointSlice's
// namespace/name.
type routeState struct {
	vpc       string
	prefix    *net.IPNet
	sid       net.IP
	installed bool
	// absentSince is the zero Time while this route is desired. It is set the
	// moment a nil desired value is first observed, and cleared again if the
	// route is reactivated before Sweep tears it down.
	absentSince time.Time
}

// vrfState tracks one VPC's VRF device lifecycle, keyed by vpc.
type vrfState struct {
	tableID   uint32
	installed bool
	// absentSince is the zero Time while at least one route still references
	// this VPC, whether installed or itself within its grace period. Only once
	// every such route is gone does this VPC's teardown clock start.
	absentSince time.Time
	// gatewayPublished is true once this VPC's return-path advertisement has
	// been published. Set at most once per VRF lifetime, so a transient resolve
	// or publish failure retries on the next SetDesired rather than being
	// abandoned for the VRF's remaining lifetime.
	gatewayPublished bool
}

// Store is the in-process desired-versus-applied reconciler for this sidecar's
// two granularities: route lifecycle keyed per pod, and VRF lifecycle keyed per
// VPC and rolled up from every route referencing it.
//
// Teardown is deliberately delayed by a grace period rather than applied
// synchronously, which is why SetDesired and Sweep replace a single reconcile
// call: SetDesired applies transitions up immediately and only starts a clock
// on transitions down, and Sweep acts once that clock expires.
type Store struct {
	mu      sync.Mutex
	backend Backend
	grace   time.Duration
	metrics *Metrics

	// gatewayPublisher and gatewayResolver are nil by default. See
	// SetGatewayPublisher for what enabling them does.
	gatewayPublisher GatewayPublisher
	gatewayResolver  GatewayAddressResolver

	routes map[string]*routeState
	vrfs   map[string]*vrfState
}

// NewStore returns a Store that converges against backend, delaying teardown of
// any route or VRF by grace after it leaves desired state. metrics may be nil,
// as tests commonly pass.
func NewStore(backend Backend, grace time.Duration, metrics *Metrics) *Store {
	return &Store{
		backend: backend,
		grace:   grace,
		metrics: metrics,
		routes:  make(map[string]*routeState),
		vrfs:    make(map[string]*vrfState),
	}
}

// SetGatewayPublisher enables this Store to publish and withdraw a return-path
// BGPAdvertisement for each VPC it manages a VRF for. Without one, a backend's
// reply traffic has no SRv6 route back to this node.
//
// Both arguments default to nil, which is fully inert: a deployment with no
// gateway address provisioned has nothing for the resolver to find anyway. Call
// this once, before the first SetDesired, and only when both a node identity
// and a real resolver are configured.
func (s *Store) SetGatewayPublisher(publisher GatewayPublisher, resolver GatewayAddressResolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gatewayPublisher = publisher
	s.gatewayResolver = resolver
}

// publishGateway attempts to publish vpc's return-path advertisement once, the
// first time its VRF is created. Called with s.mu held.
//
// A resolve failure because nothing has provisioned a gateway address yet is
// logged at debug and left for the next SetDesired to retry, not treated as a
// reconcile error. Any other error is logged at warn and likewise retried,
// rather than failing the route reconcile that triggered it: a missing return
// path degrades this VPC's ingress traffic, and withholding the forward-path
// route as well would not improve it.
func (s *Store) publishGateway(ctx context.Context, vpc string, v *vrfState) {
	if s.gatewayPublisher == nil || s.gatewayResolver == nil || v.gatewayPublished {
		return
	}
	addr, err := s.gatewayResolver.ResolveGatewayAddress(vpc)
	if err != nil {
		if errors.Is(err, ErrGatewayAddressNotProvisioned) {
			slog.Debug("ingresssidecar: no gateway address provisioned yet, will retry", "vpc", vpc, "err", err)
		} else {
			slog.Warn("ingresssidecar: resolve gateway address", "vpc", vpc, "err", err)
		}
		return
	}
	if err := s.gatewayPublisher.PublishGateway(ctx, vpc, addr); err != nil {
		slog.Warn("ingresssidecar: publish gateway advertisement", "vpc", vpc, "err", err)
		return
	}
	v.gatewayPublished = true
}

// withdrawGateway is publishGateway's counterpart, called with s.mu held once a
// VPC's VRF is about to be removed. Best-effort: a failure is logged rather
// than propagated, since it must never block the kernel-side delete that
// follows, or a transient API error would leave a VRF stuck mid-teardown.
// Garbage collection reaps an advertisement left behind by a failed withdraw
// like any other orphan.
func (s *Store) withdrawGateway(ctx context.Context, vpc string, v *vrfState) {
	if s.gatewayPublisher == nil || !v.gatewayPublished {
		return
	}
	if err := s.gatewayPublisher.WithdrawGateway(ctx, vpc); err != nil {
		slog.Warn("ingresssidecar: withdraw gateway advertisement", "vpc", vpc, "err", err)
	}
}

// SetDesired updates the desired state for the route identified by key, an
// EndpointSlice's namespace and name.
//
// A nil desired means the slice is gone or no longer selected, which starts, or
// leaves running, that route's teardown grace period rather than removing it
// immediately. A non-nil desired ensures the route's VRF and its own route
// exist immediately: no delay on the way up, only on the way down. A route
// reappearing before its grace period elapses, or a VPC gaining a new route
// before its VRF's does, cancels the pending teardown outright.
func (s *Store) SetDesired(ctx context.Context, key string, desired *DesiredRoute) (err error) {
	if s.metrics != nil {
		timer := prometheusTimer(s.metrics)
		defer func() { timer() }()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if desired == nil {
		if r, ok := s.routes[key]; ok && r.absentSince.IsZero() {
			r.absentSince = time.Now()
		}
		return nil
	}

	v, ok := s.vrfs[desired.VPC]
	if !ok {
		v = &vrfState{}
		s.vrfs[desired.VPC] = v
	}
	v.absentSince = time.Time{} // this VPC has a live pod again

	if !v.installed {
		tableID, verr := s.backend.EnsureVRF(desired.VPC)
		if verr != nil {
			s.countError("ensure_vrf")
			return fmt.Errorf("ensure VRF for vpc %s: %w", desired.VPC, verr)
		}
		v.installed = true
		v.tableID = tableID
		s.vrfActiveDelta(1)
	}
	s.publishGateway(ctx, desired.VPC, v)

	if rerr := s.backend.EnsureRoute(desired.Prefix, desired.SID, v.tableID); rerr != nil {
		s.countError("ensure_route")
		return fmt.Errorf("ensure route for %s: %w", desired.Prefix, rerr)
	}

	r, ok := s.routes[key]
	if !ok {
		r = &routeState{}
		s.routes[key] = r
	}
	r.vpc = desired.VPC
	r.prefix = desired.Prefix
	r.sid = desired.SID
	r.absentSince = time.Time{} // (re)activated -- cancel any pending teardown
	if !r.installed {
		r.installed = true
		s.routeActiveDelta(1)
	}
	return nil
}

// Sweep advances every pending teardown whose grace period has elapsed as of
// now, removing kernel state and forgetting it.
//
// Routes are processed first. A VPC's grace period only starts once Sweep
// observes no remaining route referencing it, installed or still within its own
// grace, so the two timers can never overlap and a VPC is never torn down while
// one of its routes might still come back.
//
// Call this periodically, never reactively: VRF teardown is an aggregate
// condition over many routes, not one watched object's transition.
func (s *Store) Sweep(ctx context.Context, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pendingRoutes, pendingVRFs := 0, 0

	liveVPCs := make(map[string]struct{}, len(s.vrfs))
	for key, r := range s.routes {
		if r.absentSince.IsZero() {
			liveVPCs[r.vpc] = struct{}{}
			continue
		}
		if now.Sub(r.absentSince) < s.grace {
			liveVPCs[r.vpc] = struct{}{} // still in its own grace -- keeps the VPC live too
			pendingRoutes++
			continue
		}
		if r.installed && s.prefixClaimedElsewhereLocked(key, r, now) {
			// One backend address reaches this sidecar through more than one
			// EndpointSlice, sharing a single kernel route. Removing it while
			// another slice is live blackholes a healthy backend.
			s.routeActiveDelta(-1)
			delete(s.routes, key)
			continue
		}
		if r.installed {
			v, ok := s.vrfs[r.vpc]
			if !ok {
				slog.Error("ingresssidecar: sweep found route with no tracked VRF", "key", key, "vpc", r.vpc)
			} else if err := s.backend.RemoveRoute(r.prefix, v.tableID); err != nil {
				s.countError("remove_route")
				slog.Error("ingresssidecar: remove route", "key", key, "vpc", r.vpc, "error", err)
				liveVPCs[r.vpc] = struct{}{} // keep the VPC alive; retry next sweep
				pendingRoutes++
				continue
			}
			s.routeActiveDelta(-1)
		}
		delete(s.routes, key)
	}

	for vpc, v := range s.vrfs {
		if _, live := liveVPCs[vpc]; live {
			v.absentSince = time.Time{}
			continue
		}
		if v.absentSince.IsZero() {
			v.absentSince = now
			pendingVRFs++
			continue
		}
		if now.Sub(v.absentSince) < s.grace {
			pendingVRFs++
			continue
		}
		if v.installed {
			s.withdrawGateway(ctx, vpc, v)
			if err := s.backend.RemoveVRF(vpc); err != nil {
				s.countError("remove_vrf")
				slog.Error("ingresssidecar: remove VRF", "vpc", vpc, "error", err)
				pendingVRFs++
				continue
			}
			s.vrfActiveDelta(-1)
		}
		delete(s.vrfs, vpc)
	}

	if s.metrics != nil {
		s.metrics.RoutePending.Set(float64(pendingRoutes))
		s.metrics.VRFPending.Set(float64(pendingVRFs))
	}
}

// Inventory seeds Store with every managed VRF device, and its installed
// routes, already present on the host at process start.
//
// Call it once, after every EndpointSlice existing at boot has been through
// SetDesired, and before the first Sweep. Anything already known by then is
// left alone, its claim having been made by that seeding.
//
// Anything Inventory itself has to seed is by construction missing that claim:
// either genuinely orphaned while this sidecar was down, or belonging to a slice
// that is gone or unready for some other reason. Such state is seeded with an
// ordinary grace period starting now, rather than torn down on sight, which
// gives a slightly late update a chance to reclaim it, and rather than kept
// alive forever.
func (s *Store) Inventory(ctx context.Context, now time.Time) error {
	infos, err := s.backend.ListVRFs()
	if err != nil {
		return fmt.Errorf("list existing VRFs: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, info := range infos {
		v, ok := s.vrfs[info.VPC]
		if !ok {
			v = &vrfState{tableID: info.TableID, installed: true, absentSince: now}
			s.vrfs[info.VPC] = v
			s.vrfActiveDelta(1)
		}

		routes, err := s.backend.ListRoutes(v.tableID)
		if err != nil {
			return fmt.Errorf("list existing routes for vpc %s (table %d): %w", info.VPC, v.tableID, err)
		}
		for _, route := range routes {
			if s.routeKnownLocked(info.VPC, route.Prefix) {
				continue // a live EndpointSlice's reconcile already claimed this one
			}
			key := fmt.Sprintf("boot/%s/%s", info.VPC, route.Prefix.String())
			s.routes[key] = &routeState{
				vpc: info.VPC, prefix: route.Prefix, sid: route.SID,
				installed: true, absentSince: now,
			}
			s.routeActiveDelta(1)
		}
	}
	return nil
}

// prefixClaimedElsewhereLocked reports whether some other tracked route still
// needs the kernel state installed for r's VPC and prefix, either because it
// is desired or because its own grace period has not elapsed. Callers must
// hold s.mu.
func (s *Store) prefixClaimedElsewhereLocked(key string, r *routeState, now time.Time) bool {
	for otherKey, other := range s.routes {
		if otherKey == key || other.vpc != r.vpc || other.prefix.String() != r.prefix.String() {
			continue
		}
		if other.absentSince.IsZero() || now.Sub(other.absentSince) < s.grace {
			return true
		}
	}
	return false
}

// routeKnownLocked reports whether an already-tracked route shares vpc and
// prefix with the given kernel route, meaning a live EndpointSlice claims it
// and it is not orphaned. Callers must hold s.mu.
func (s *Store) routeKnownLocked(vpc string, prefix *net.IPNet) bool {
	for _, r := range s.routes {
		if r.vpc == vpc && r.prefix.String() == prefix.String() {
			return true
		}
	}
	return false
}

func (s *Store) countError(kind string) {
	if s.metrics != nil {
		s.metrics.ReconcileErrs.WithLabelValues(kind).Inc()
	}
}

// vrfActiveDelta and routeActiveDelta adjust the active-count gauges by delta,
// doing nothing when metrics were not configured.
func (s *Store) vrfActiveDelta(delta float64) {
	if s.metrics != nil {
		s.metrics.VRFActive.Add(delta)
	}
}

func (s *Store) routeActiveDelta(delta float64) {
	if s.metrics != nil {
		s.metrics.RouteActive.Add(delta)
	}
}

// prometheusTimer starts a wall-clock timer and returns a function that, on
// its own call, records the elapsed duration against m.ReconcileTime.
func prometheusTimer(m *Metrics) func() {
	start := time.Now()
	return func() { m.ReconcileTime.Observe(time.Since(start).Seconds()) }
}
