// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
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
	// absentSince is the zero Time while this route is desired. SetDesired
	// sets it the moment a nil desired value is first observed for this
	// key, and clears it again if the route is reactivated before Sweep
	// tears it down — see SetDesired and Sweep.
	absentSince time.Time
}

// vrfState tracks one VPC's VRF device lifecycle, keyed by vpc.
type vrfState struct {
	tableID   uint32
	installed bool
	// absentSince is the zero Time while at least one route still
	// references this VPC (installed or itself still within its own grace
	// period — see Sweep). Only once every such route is gone does this
	// VPC's own teardown grace period start.
	absentSince time.Time
}

// Store is the in-process desired/applied-state reconciler for this
// sidecar's two granularities (§1 of the plan): route lifecycle keyed per
// pod, VRF lifecycle keyed per VPC and rolled up from every route
// referencing it. Mirrors internal/gateway's Engine and
// internal/runtime/gobgp's GoBGPRuntime in shape — a mutex-protected map of
// applied state, converged via Backend calls — except teardown here is
// intentionally delayed by a grace period rather than applied synchronously
// (§9 item 1 of the plan's teardown-race decision), so SetDesired/Sweep
// replace a single Reconcile/Apply call: SetDesired applies "up" transitions
// immediately and only starts a clock on "down" ones; Sweep is what actually
// acts once that clock expires.
type Store struct {
	mu      sync.Mutex
	backend Backend
	grace   time.Duration
	metrics *Metrics

	routes map[string]*routeState
	vrfs   map[string]*vrfState
}

// NewStore returns a Store that converges against backend, delaying
// teardown of any route or VRF by grace after it drops out of desired
// state. metrics may be nil (tests commonly pass nil; production callers
// always pass a real *Metrics).
func NewStore(backend Backend, grace time.Duration, metrics *Metrics) *Store {
	return &Store{
		backend: backend,
		grace:   grace,
		metrics: metrics,
		routes:  make(map[string]*routeState),
		vrfs:    make(map[string]*vrfState),
	}
}

// SetDesired updates the desired state for the route identified by key —
// an EndpointSlice's namespace/name (see Reconciler). desired == nil means
// the EndpointSlice is gone or no longer selected (BuildDesiredRoute
// returned nil for a not-yet-ready one, or the object was deleted): this
// starts (or leaves running) that route's teardown grace period rather than
// removing it immediately. desired != nil ensures the route's VRF and its
// own seg6 route exist immediately — no delay on the way up, only on the
// way down, the asymmetry §9 item 1 of the plan calls for. A route
// reappearing before its own grace period elapses, or a VPC gaining a new
// route before its VRF's grace period elapses, cancels that pending
// teardown outright.
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

// Sweep advances every pending teardown whose grace period has elapsed as
// of now, removing kernel state and forgetting it. Routes are processed
// first; a VPC's own grace period only starts once Sweep observes no
// remaining route — installed or still within its own grace — referencing
// it, so the two timers can never overlap: a VPC is never torn down while
// any of its routes still might come back. Call this periodically (see
// RunSweeper), never reactively — VRF-level teardown is an aggregate
// condition over potentially many routes, not a single watched object's own
// transition.
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

// Inventory seeds Store with every Galactic-managed VRF device (and its
// currently-installed seg6 routes) already present on the host at process
// start — §9 item 2 of the plan's startup-reconcile-safety decision.
//
// Call this once, after the manager's caches have synced (so every
// EndpointSlice existing at boot has already been through SetDesired via
// the controller's own initial reconcile pass — see Reconciler) but before
// the first Sweep runs. A VPC/route already known by that point is left
// alone: a live EndpointSlice's reconcile beat Inventory here, so its
// absentSince is already clear. Anything Inventory itself has to seed is,
// by construction, missing that reconcile — either a VPC/pod truly orphaned
// while this sidecar was down, or one whose EndpointSlice hasn't reconciled
// yet for some other reason — so it's seeded with an ordinary grace period
// starting now rather than torn down on sight (giving a slightly late
// EndpointSlice reconcile a chance to reclaim it) and rather than kept
// alive forever (the pre-#377-revision failure mode this decision exists to
// avoid).
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

// routeKnownLocked reports whether some already-tracked route shares vpc
// and prefix with the given kernel route — i.e. it's not orphaned, a live
// EndpointSlice already claims it. Callers must hold s.mu.
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

// vrfActiveDelta and routeActiveDelta adjust the vrf_active/route_active
// gauges by delta, no-oping if metrics weren't configured (tests commonly
// pass nil — see NewStore).
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
