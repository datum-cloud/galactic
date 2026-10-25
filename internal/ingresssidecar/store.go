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
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// gatewayRetriesPerSweep bounds how many VPCs one sweep retries publishing a
// gateway advertisement for, and gatewayRetryTimeout each attempt, so a slow
// API delays a sweep by a bounded amount. Variables so tests can shorten them.
var (
	gatewayRetriesPerSweep = 4
	gatewayRetryTimeout    = 10 * time.Second
)

// routeState tracks one pod's route lifecycle, keyed by its EndpointSlice's
// namespace/name.
type routeState struct {
	vpc       string
	prefix    *net.IPNet
	sid       net.IP
	installed bool
	// pending is true while the latest desired value has not been fully
	// applied, typically because the shared eBPF datapath was not loaded yet.
	// The route still counts as desired, so Inventory does not mistake its
	// host state for an orphan, and every Sweep retries applying it.
	pending bool
	// absentSince is the zero Time while this route is desired. It is set the
	// moment a nil desired value is first observed, and cleared again if the
	// route is reactivated before Sweep tears it down.
	absentSince time.Time
	// pendingSince is when this route last became desired and apply-pending,
	// or the zero Time while it is not both. A retry or a newer update of a
	// route already pending keeps it: the claim has been unapplied since then.
	pendingSince time.Time
}

// claim reports whether r counts as a desired route claim, and as one whose
// latest update is not applied yet.
func (r *routeState) claim() (desired, pending bool) {
	desired = r.absentSince.IsZero()
	return desired, desired && r.pending
}

// vrfState tracks one VPC's VRF device lifecycle, keyed by vpc.
type vrfState struct {
	tableID   uint32
	installed bool
	// absentSince is the zero Time while at least one route still references
	// this VPC, whether installed or itself within its grace period. Only once
	// every such route is gone does this VPC's teardown clock start.
	absentSince time.Time
	// gatewayPublished is true while this VPC's return-path advertisement is
	// published, from a successful publish until a successful withdrawal. A
	// failed resolve or publish is retried on the next SetDesired and by
	// every Sweep (retryGateways) until it succeeds.
	gatewayPublished bool
	// gatewayState is where this VRF's publication stands (GatewayAwaiting*,
	// GatewayPublished), and gatewayWaitingSince when it last started waiting
	// while counted. Both are bookkeeping for GatewayMetrics only.
	gatewayState        string
	gatewayWaitingSince time.Time
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
	// gatewayCursor rotates where retryGateways starts, so a VPC that keeps
	// failing cannot starve the others of retries.
	gatewayCursor int
	// gatewayInFlight holds the VPCs retryGateways is publishing or
	// withdrawing for outside the lock. publishGateway skips them, so no
	// other publish for the VPC interleaves with that call; a VRF it skips
	// is retried by a later Sweep.
	gatewayInFlight map[string]struct{}

	// gatewayMetrics is nil unless SetGatewayMetrics was called.
	// gatewayCounts holds each counted VRF's state, kept in step at every
	// change, and gatewayOldest the longest wait, rescanned over the VRFs
	// (one per VPC) only when the VRF holding it stops waiting
	// (gatewayOldestDirty).
	gatewayMetrics     *GatewayMetrics
	gatewayCounts      map[string]int
	gatewayOldest      time.Time
	gatewayOldestDirty bool

	routes map[string]*routeState
	vrfs   map[string]*vrfState

	// convergence is nil unless SetConvergenceMetrics was called. The claim
	// counts are kept in step with routes at every change, and pendingQueue
	// holds each claim in the order it became pending, so publishing them
	// never scans every route.
	convergence   *ConvergenceMetrics
	clock         func() time.Time
	desiredClaims int
	pendingClaims int
	pendingQueue  []pendingEntry

	// inputs holds nil unless SetInputMetrics was called. It is the seed's
	// and the reconciler's, kept here so both reach it without taking s.mu.
	inputs atomic.Pointer[InputMetrics]

	// datapath is nil unless SetDatapathMetrics was called.
	datapath *DatapathMetrics

	// generation is the backend's DatapathGeneration as of the last time every
	// tracked VRF and route was known to be written against it, or empty
	// before the first successful read. reapplyPending is set when a reapply
	// pass left something unapplied, so the next Sweep retries it even though
	// the generation has not moved again.
	generation     string
	reapplyPending bool

	// nodeSourceMetrics is nil unless SetNodeSourceMetrics configured it.
	nodeSourceMetrics *NodeSourceMetrics
	// nodeSourceStatus is the last node source check's status, so a repeated
	// failure is logged once.
	nodeSourceStatus string
}

// NewStore returns a Store that converges against backend, delaying teardown of
// any route or VRF by grace after it leaves desired state. metrics may be nil,
// as tests commonly pass.
func NewStore(backend Backend, grace time.Duration, metrics *Metrics) *Store {
	return &Store{
		backend:         backend,
		grace:           grace,
		metrics:         metrics,
		routes:          make(map[string]*routeState),
		vrfs:            make(map[string]*vrfState),
		gatewayInFlight: make(map[string]struct{}),
		clock:           time.Now,
	}
}

// SetConvergenceMetrics has this Store report its desired and apply-pending
// claims, overdue teardown and backend operations to m. Call it once, before
// the first SetDesired.
func (s *Store) SetConvergenceMetrics(m *ConvergenceMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.convergence = m
	s.publishClaimsLocked()
}

// pendingEntry records that r became pending at since. It is stale once r
// has applied, stopped being desired, or become pending again later.
type pendingEntry struct {
	r     *routeState
	since time.Time
}

func (e pendingEntry) live() bool {
	_, pending := e.r.claim()
	return pending && e.r.pendingSince.Equal(e.since)
}

// claimChangedLocked updates the claim counts and pending starts after r
// changed from a claim that was wasDesired and wasPending. Callers must hold
// s.mu.
func (s *Store) claimChangedLocked(r *routeState, wasDesired, wasPending bool) {
	desired, pending := r.claim()
	s.desiredClaims += boolDelta(wasDesired, desired)
	s.pendingClaims += boolDelta(wasPending, pending)
	switch {
	case pending && !wasPending:
		r.pendingSince = s.clock()
		s.pendingQueue = append(s.pendingQueue, pendingEntry{r: r, since: r.pendingSince})
	case !pending && wasPending:
		r.pendingSince = time.Time{} // its queue entry is now stale
	}
}

// oldestPendingLocked returns when the longest-pending claim became pending,
// or the zero Time when none is pending. Stale entries are dropped from the
// front as they surface, and the queue is compacted once they outnumber the
// live ones, so the cost is constant per claim transition however the
// backlog drains. Callers must hold s.mu.
func (s *Store) oldestPendingLocked() time.Time {
	if s.pendingClaims == 0 {
		s.pendingQueue = s.pendingQueue[:0]
		return time.Time{}
	}
	if len(s.pendingQueue) > 2*s.pendingClaims+64 {
		live := s.pendingQueue[:0]
		for _, e := range s.pendingQueue {
			if e.live() {
				live = append(live, e)
			}
		}
		clear(s.pendingQueue[len(live):])
		s.pendingQueue = live
	}
	for len(s.pendingQueue) > 0 && !s.pendingQueue[0].live() {
		s.pendingQueue[0] = pendingEntry{}
		s.pendingQueue = s.pendingQueue[1:]
	}
	if len(s.pendingQueue) == 0 {
		return time.Time{}
	}
	return s.pendingQueue[0].since
}

// publishClaimsLocked publishes the claim counts and the oldest pending
// start. Callers must hold s.mu.
func (s *Store) publishClaimsLocked() {
	s.convergence.claims(s.desiredClaims, s.pendingClaims, s.oldestPendingLocked())
}

func boolDelta(was, is bool) int {
	switch {
	case is && !was:
		return 1
	case was && !is:
		return -1
	}
	return 0
}

// SetInputMetrics has the startup seed and the EndpointSlice reconciler
// report each slice's input state to m. Call it once, before either runs.
func (s *Store) SetInputMetrics(m *InputMetrics) {
	s.inputs.Store(m)
}

// inputMetrics returns what SetInputMetrics set.
func (s *Store) inputMetrics() *InputMetrics {
	return s.inputs.Load()
}

// SetDatapathMetrics has this Store report each sweep's datapath checks and
// reapply passes to m. Call it once, before the first Sweep.
func (s *Store) SetDatapathMetrics(m *DatapathMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.datapath = m
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

// SetGatewayMetrics has this Store report gateway publication state and
// operations to m, counting the VRFs it already tracks. Call it after
// SetGatewayPublisher.
func (s *Store) SetGatewayMetrics(m *GatewayMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gatewayMetrics = m
	s.gatewayCounts = map[string]int{}
	s.gatewayOldest, s.gatewayOldestDirty = time.Time{}, false
	for _, v := range s.vrfs {
		v.gatewayWaitingSince = time.Time{}
		s.gatewayChangedLocked(v, "")
	}
	s.publishGatewayStateLocked()
}

// gatewayCounted is the state a VRF contributes to gateway_vrfs: none while
// publication is disabled, before the VRF is installed, or while it drains.
func (s *Store) gatewayCounted(v *vrfState) string {
	if s.gatewayPublisher == nil || s.gatewayResolver == nil || !v.installed || !v.absentSince.IsZero() {
		return ""
	}
	if v.gatewayPublished {
		return GatewayPublished
	}
	if v.gatewayState == "" {
		return GatewayAwaitingAddress
	}
	return v.gatewayState
}

// gatewayChangedLocked updates the gateway counts after v changed from
// contributing before. Callers must hold s.mu.
func (s *Store) gatewayChangedLocked(v *vrfState, before string) {
	if s.gatewayMetrics == nil {
		return
	}
	after := s.gatewayCounted(v)
	if before == after {
		return
	}
	if before != "" {
		s.gatewayCounts[before]--
	}
	if after != "" {
		s.gatewayCounts[after]++
	}
	waitedBefore := before != "" && before != GatewayPublished
	waitsAfter := after != "" && after != GatewayPublished
	switch {
	case waitsAfter && !waitedBefore:
		v.gatewayWaitingSince = s.gatewayMetrics.clock()
		if s.gatewayOldest.IsZero() || v.gatewayWaitingSince.Before(s.gatewayOldest) {
			s.gatewayOldest = v.gatewayWaitingSince
		}
	case waitedBefore && !waitsAfter:
		if v.gatewayWaitingSince.Equal(s.gatewayOldest) {
			s.gatewayOldestDirty = true
		}
		v.gatewayWaitingSince = time.Time{}
	}
	s.publishGatewayStateLocked()
}

// publishGatewayStateLocked publishes the gateway counts and the oldest wait.
// Callers must hold s.mu.
func (s *Store) publishGatewayStateLocked() {
	if s.gatewayMetrics == nil {
		return
	}
	if s.gatewayOldestDirty {
		s.gatewayOldest, s.gatewayOldestDirty = time.Time{}, false
		for _, v := range s.vrfs {
			if !v.gatewayWaitingSince.IsZero() &&
				(s.gatewayOldest.IsZero() || v.gatewayWaitingSince.Before(s.gatewayOldest)) {
				s.gatewayOldest = v.gatewayWaitingSince
			}
		}
	}
	s.gatewayMetrics.publish(s.gatewayCounts, s.gatewayOldest)
}

// publishGateway attempts to publish vpc's return-path advertisement once,
// from SetDesired, while its VRF has none. Called with s.mu held. It skips a
// VPC retryGateways is calling the API for.
//
// A resolve failure because nothing has provisioned a gateway address yet is
// logged at debug and left for the next SetDesired or Sweep to retry, not
// treated as a reconcile error. Any other error is logged at warn and likewise
// retried, rather than failing the route reconcile that triggered it: a
// missing return path degrades this VPC's ingress traffic, and withholding the
// forward-path route as well would not improve it.
func (s *Store) publishGateway(ctx context.Context, vpc string, v *vrfState) {
	if s.gatewayPublisher == nil || s.gatewayResolver == nil || v.gatewayPublished || s.inFlightLocked(vpc) {
		return
	}
	before := s.gatewayCounted(v)
	defer func() { s.gatewayChangedLocked(v, before) }()
	addr, err := s.gatewayResolver.ResolveGatewayAddress(vpc)
	if err != nil {
		v.gatewayState = GatewayAwaitingAddress
		if errors.Is(err, ErrGatewayAddressNotProvisioned) {
			s.gatewayMetrics.operation(GatewayOpResolve, GatewayNotProvisioned)
			slog.Debug("ingresssidecar: no gateway address provisioned yet, will retry", "vpc", vpc, "err", err)
		} else {
			s.gatewayMetrics.operation(GatewayOpResolve, GatewayError)
			slog.Warn("ingresssidecar: resolve gateway address", "vpc", vpc, "err", err)
		}
		return
	}
	s.gatewayMetrics.operation(GatewayOpResolve, GatewaySuccess)
	v.gatewayState = GatewayAwaitingPublication
	if err := s.gatewayPublisher.PublishGateway(ctx, vpc, addr); err != nil {
		s.gatewayMetrics.operation(GatewayOpPublish, GatewayError)
		slog.Warn("ingresssidecar: publish gateway advertisement", "vpc", vpc, "err", err)
		return
	}
	s.gatewayMetrics.operation(GatewayOpPublish, GatewaySuccess)
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
		s.gatewayMetrics.operation(GatewayOpWithdraw, GatewayError)
		slog.Warn("ingresssidecar: withdraw gateway advertisement", "vpc", vpc, "err", err)
		return
	}
	s.gatewayMetrics.operation(GatewayOpWithdraw, GatewaySuccess)
	// Withdrawn: if removing the VRF then fails and the VPC comes back, it is
	// published again.
	v.gatewayPublished = false
}

// retryGateways publishes the gateway advertisement of up to
// gatewayRetriesPerSweep desired VRFs whose publication has not succeeded,
// so a failed publish recovers without waiting for another EndpointSlice
// update. One attempt per VPC, however many routes it has, starting where the
// last sweep stopped.
//
// The API calls run without s.mu, each bounded by gatewayRetryTimeout and
// cancelled with ctx, while the VPC is marked in flight. A successful publish
// belongs to whichever VRF tracks the VPC when it completes, the one it was
// made for or a replacement; the advertisement depends only on the VPC, and
// teardown withdraws it as usual. With no VRF left for the VPC it is
// withdrawn again before the VPC stops being in flight.
//
// Sweep has one caller, the sweeper goroutine, so no VRF is removed while
// these calls run today; crediting a replacement and withdrawing for a removed
// VRF keep the result right if that changes. A SetDesired for a VPC in flight
// does not publish it, so if the retry then fails the VPC waits for the next
// Sweep. The attempts can lengthen a sweep by up to gatewayRetriesPerSweep
// times gatewayRetryTimeout, which delays the next sweep's teardown, not this
// one's: teardown runs first.
func (s *Store) retryGateways(ctx context.Context) {
	s.mu.Lock()
	publisher, resolver := s.gatewayPublisher, s.gatewayResolver
	m := s.gatewayMetrics
	if publisher == nil || resolver == nil {
		s.mu.Unlock()
		return
	}
	var pending []string
	for vpc, v := range s.vrfs {
		if v.installed && v.absentSince.IsZero() && !v.gatewayPublished && !s.inFlightLocked(vpc) {
			pending = append(pending, vpc)
		}
	}
	sort.Strings(pending)
	n := min(len(pending), gatewayRetriesPerSweep)
	vpcs := make([]string, 0, n)
	for i := range n {
		vpc := pending[(s.gatewayCursor+i)%len(pending)]
		s.gatewayInFlight[vpc] = struct{}{}
		vpcs = append(vpcs, vpc)
	}
	s.gatewayCursor += n
	s.mu.Unlock()

	for _, vpc := range vpcs {
		s.retryGateway(ctx, m, publisher, resolver, vpc)
	}
}

// retryGateway makes one retryGateways attempt for vpc, which the caller
// marked in flight, records it to m, and clears the mark.
func (s *Store) retryGateway(
	ctx context.Context, m *GatewayMetrics, publisher GatewayPublisher, resolver GatewayAddressResolver, vpc string,
) {
	// Clear the mark however this returns, a panic included, or the VPC
	// would never be published again.
	defer func() {
		s.mu.Lock()
		delete(s.gatewayInFlight, vpc)
		s.mu.Unlock()
	}()
	if ctx.Err() != nil {
		return // shutting down
	}
	state, err := publishOnce(ctx, m, publisher, resolver, vpc)
	s.mu.Lock()
	v := s.vrfs[vpc]
	if v != nil {
		before := s.gatewayCounted(v)
		if err == nil {
			v.gatewayPublished = true
		} else {
			v.gatewayState = state
		}
		s.gatewayChangedLocked(v, before)
	}
	s.mu.Unlock()

	switch {
	case err == nil && v == nil:
		wctx, cancel := context.WithTimeout(ctx, gatewayRetryTimeout)
		defer cancel()
		if werr := publisher.WithdrawGateway(wctx, vpc); werr != nil {
			m.operation(GatewayOpWithdraw, GatewayError)
			slog.Warn("ingresssidecar: withdraw a gateway advertisement published for a removed VRF",
				"vpc", vpc, "err", werr)
			return
		}
		m.operation(GatewayOpWithdraw, GatewaySuccess)
	case ctx.Err() != nil:
		// Shutting down: the next sidecar retries.
	case errors.Is(err, ErrGatewayAddressNotProvisioned):
		slog.Debug("ingresssidecar: no gateway address provisioned yet, will retry", "vpc", vpc, "err", err)
	case err != nil:
		slog.Warn("ingresssidecar: retry gateway advertisement", "vpc", vpc, "err", err)
	}
}

// inFlightLocked reports whether retryGateways is calling the API for vpc.
func (s *Store) inFlightLocked(vpc string) bool {
	_, ok := s.gatewayInFlight[vpc]
	return ok
}

// publishOnce resolves vpc's gateway address and publishes it, within
// gatewayRetryTimeout, recording each step to m. On failure it returns the
// state the VPC is left waiting in.
func publishOnce(
	ctx context.Context, m *GatewayMetrics, publisher GatewayPublisher, resolver GatewayAddressResolver, vpc string,
) (string, error) {
	addr, err := resolver.ResolveGatewayAddress(vpc)
	if err != nil {
		if errors.Is(err, ErrGatewayAddressNotProvisioned) {
			m.operation(GatewayOpResolve, GatewayNotProvisioned)
		} else {
			m.operation(GatewayOpResolve, GatewayError)
		}
		return GatewayAwaitingAddress, err
	}
	m.operation(GatewayOpResolve, GatewaySuccess)
	pctx, cancel := context.WithTimeout(ctx, gatewayRetryTimeout)
	defer cancel()
	if err := publisher.PublishGateway(pctx, vpc, addr); err != nil {
		m.operation(GatewayOpPublish, GatewayError)
		return GatewayAwaitingPublication, err
	}
	m.operation(GatewayOpPublish, GatewaySuccess)
	return GatewayPublished, nil
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
//
// A non-nil desired is recorded before it is applied, so a failed apply still
// leaves the route desired. Sweep retries it until it succeeds.
func (s *Store) SetDesired(ctx context.Context, key string, desired *DesiredRoute) (err error) {
	if s.metrics != nil {
		timer := prometheusTimer(s.metrics)
		defer func() { timer() }()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.publishClaimsLocked()

	if desired == nil {
		if r, ok := s.routes[key]; ok && r.absentSince.IsZero() {
			wasDesired, wasPending := r.claim()
			r.absentSince = time.Now()
			s.claimChangedLocked(r, wasDesired, wasPending)
		}
		return nil
	}

	// Read before the first write rather than after it: a reload landing
	// between the two then shows up on the next Sweep as a changed generation
	// instead of being mistaken for the one those writes went into.
	// A baseline, not a check: Sweep's own read reports a failure.
	if s.generation == "" {
		if gen, gerr := s.backend.DatapathGeneration(); gerr == nil {
			s.generation = gen
		}
	}

	var wasDesired, wasPending bool
	r, ok := s.routes[key]
	if ok {
		wasDesired, wasPending = r.claim()
	} else {
		r = &routeState{}
		s.routes[key] = r
	}
	r.vpc = desired.VPC
	r.prefix = desired.Prefix
	r.sid = desired.SID
	r.absentSince = time.Time{} // (re)activated -- cancel any pending teardown
	r.pending = true
	s.claimChangedLocked(r, wasDesired, wasPending)
	return s.applyLocked(ctx, r)
}

// applyLocked ensures r's VRF and r itself exist on the host, clearing
// r.pending once both do. Callers must hold s.mu.
func (s *Store) applyLocked(ctx context.Context, r *routeState) error {
	v, ok := s.vrfs[r.vpc]
	if !ok {
		v = &vrfState{}
		s.vrfs[r.vpc] = v
	}
	before := s.gatewayCounted(v)
	v.absentSince = time.Time{} // this VPC has a live pod again
	s.gatewayChangedLocked(v, before)

	if !v.installed {
		tableID, verr := s.backend.EnsureVRF(r.vpc)
		s.convergence.operation(OpEnsureVRF, verr)
		if verr != nil {
			s.countError("ensure_vrf")
			return fmt.Errorf("ensure VRF for vpc %s: %w", r.vpc, verr)
		}
		beforeInstall := s.gatewayCounted(v)
		v.installed = true
		v.tableID = tableID
		s.gatewayChangedLocked(v, beforeInstall)
		s.vrfActiveDelta(1)
	}
	s.publishGateway(ctx, r.vpc, v)

	rerr := s.backend.EnsureRoute(r.prefix, r.sid, v.tableID)
	s.convergence.operation(OpEnsureRoute, rerr)
	if rerr != nil {
		s.countError("ensure_route")
		return fmt.Errorf("ensure route for %s: %w", r.prefix, rerr)
	}

	wasDesired, wasPending := r.claim()
	r.pending = false
	s.claimChangedLocked(r, wasDesired, wasPending)
	if !r.installed {
		r.installed = true
		s.routeActiveDelta(1)
	}
	return nil
}

// retryPendingLocked applies every desired route an earlier SetDesired failed
// to apply. Without it, a route that failed because the datapath was not
// loaded yet waits on the reconciler's own backoff, which grows to minutes.
// Callers must hold s.mu.
func (s *Store) retryPendingLocked(ctx context.Context) {
	for key, r := range s.routes {
		if !r.pending || !r.absentSince.IsZero() {
			continue
		}
		if err := s.applyLocked(ctx, r); err != nil {
			slog.Debug("ingresssidecar: retry pending route", "key", key, "vpc", r.vpc, "error", err)
		}
	}
}

// Sweep advances every pending teardown whose grace period has elapsed as of
// now, removing kernel state and forgetting it.
//
// Routes are processed first. A VPC's grace period only starts once Sweep
// observes no remaining route referencing it, installed or still within its own
// grace, so the two timers can never overlap and a VPC is never torn down while
// one of its routes might still come back.
//
// Sweep first reapplies every live VRF and route if the shared eBPF datapath
// has been reloaded since they were written; see checkDatapathLocked. It then
// retries every desired route an earlier SetDesired failed to apply.
//
// Sweep then retries the gateway advertisements still unpublished; see
// retryGateways.
//
// Call this periodically, never reactively: VRF teardown is an aggregate
// condition over many routes, not one watched object's transition.
func (s *Store) Sweep(ctx context.Context, now time.Time) {
	s.sweepLocked(ctx, now)
	s.retryGateways(ctx)
}

// sweepLocked is Sweep's work under s.mu.
func (s *Store) sweepLocked(ctx context.Context, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.checkDatapathLocked()
	s.retryPendingLocked(ctx)
	defer s.publishClaimsLocked()
	s.checkNodeSourceLocked(now)

	pendingRoutes, pendingVRFs := 0, 0
	overdueRoutes, overdueVRFs := 0, 0

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
			} else if err := s.removeRouteLocked(r, v.tableID); err != nil {
				s.countError("remove_route")
				slog.Error("ingresssidecar: remove route", "key", key, "vpc", r.vpc, "error", err)
				liveVPCs[r.vpc] = struct{}{} // keep the VPC alive; retry next sweep
				pendingRoutes++
				overdueRoutes++
				continue
			}
			s.routeActiveDelta(-1)
		}
		delete(s.routes, key)
	}

	for vpc, v := range s.vrfs {
		if _, live := liveVPCs[vpc]; live {
			before := s.gatewayCounted(v)
			v.absentSince = time.Time{}
			s.gatewayChangedLocked(v, before)
			continue
		}
		if v.absentSince.IsZero() {
			before := s.gatewayCounted(v)
			v.absentSince = now
			s.gatewayChangedLocked(v, before)
			pendingVRFs++
			continue
		}
		if now.Sub(v.absentSince) < s.grace {
			pendingVRFs++
			continue
		}
		if v.installed {
			s.withdrawGateway(ctx, vpc, v)
			err := s.backend.RemoveVRF(vpc)
			s.convergence.operation(OpRemoveVRF, err)
			if err != nil {
				s.countError("remove_vrf")
				slog.Error("ingresssidecar: remove VRF", "vpc", vpc, "error", err)
				pendingVRFs++
				overdueVRFs++
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
	s.convergence.overdueTeardown(overdueRoutes, overdueVRFs)
}

// removeRouteLocked removes r's kernel state from tableID, recording the
// operation. Callers must hold s.mu.
func (s *Store) removeRouteLocked(r *routeState, tableID uint32) error {
	err := s.backend.RemoveRoute(r.prefix, tableID)
	s.convergence.operation(OpRemoveRoute, err)
	return err
}

// Inventory seeds Store with every managed VRF device, and its installed
// routes, already present on the host at process start.
//
// Call it after every EndpointSlice existing at boot has been through
// SetDesired, and before the first Sweep. Anything already known by then is
// left alone, its claim having been made by that seeding. A call that fails
// can be repeated, after Sweeps have run: what it seeded before failing is
// then known, and left alone the same way.
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
		} else if !v.installed {
			// A failed SetDesired tracked this VPC without learning its
			// table ID. Use the host's, or its routes are listed from, and
			// later removed from, table 0.
			v.tableID = info.TableID
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

// PruneForeignDatapath removes the rows an earlier sidecar pod on this node left
// in the shared eBPF maps, keeping those of every VRF this one tracks.
//
// Call it once, after Inventory: by then every VRF in this pod's namespace is
// tracked, so a row it does not account for belongs to a pod that is gone. It
// holds the store's lock throughout, so a VRF SetDesired creates concurrently
// is either already tracked or registers its rows after the prune.
//
// It returns how many rows it removed, which a failure part way through can
// leave above zero.
func (s *Store) PruneForeignDatapath() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keep := make(map[uint32]struct{}, len(s.vrfs))
	for _, v := range s.vrfs {
		if v.tableID != 0 {
			keep[v.tableID] = struct{}{}
		}
	}
	removed, err := s.backend.PruneDatapath(keep)
	if removed > 0 {
		slog.Info("ingresssidecar: removed rows an earlier sidecar pod left in the shared eBPF maps",
			"removed", removed)
	}
	if err != nil {
		s.countError("prune_datapath")
		return removed, fmt.Errorf("prune an earlier sidecar pod's eBPF map rows: %w", err)
	}
	return removed, nil
}

// checkDatapathLocked reapplies every live VRF and route when the backend's
// DatapathGeneration has changed since they were written, when another writer
// has removed this sidecar's rows from the shared maps, or when an earlier
// reapply pass left something unapplied. Callers must hold s.mu.
//
// Rows go missing without a reload when a sidecar pod starting on the same
// node, or the host installer's reaper, takes this live sidecar's rows for a
// deleted pod's (see PruneForeignDatapath and internal/installer/sidecarreap.go).
// Reading them back each sweep bounds that mistake to one sweep interval.
//
// Nothing else would notice. The CNI control daemon reloads the shared eBPF
// datapath independently of this sidecar, recreating its maps empty on a
// schema change and re-pinning usid_egress on every load, while this sidecar
// writes kernel state only on an EndpointSlice change, and ensures a VRF's
// datapath only when first creating it. Without this, a route lost to a reload
// stays lost until this process restarts, and usid_egress's miss on it falls
// through to the VRF's default route, looping traffic back into the VRF.
//
// A failed generation read is not acted on: it means the datapath is not
// loaded at all, which nothing here can repair, and the next successful read
// after it is loaded again will differ and trigger the reapply. It is still
// reported, as an error rather than as a healthy check.
//
// A pass's reason is generation_changed whenever the generation moved, even
// when a retry was also due; rows_missing when this check found rows gone;
// otherwise retry.
//
// The registration rows are read only while the generation is unchanged and
// no retry is due. On every other sweep, and after a reapply rewrote them, a
// last ok becomes unknown rather than standing for rows nobody read back.
func (s *Store) checkDatapathLocked() {
	defer func() { s.datapath.reapplyPending(s.reapplyPending) }()
	gen, err := s.backend.DatapathGeneration()
	if err != nil {
		s.datapath.checked(CheckGeneration, CheckError)
		s.datapath.rowsNotChecked()
		slog.Debug("ingresssidecar: read eBPF datapath generation", "err", err)
		return
	}
	s.datapath.checked(CheckGeneration, CheckOK)
	reason := ReapplyRetry
	switch {
	case gen != s.generation:
		reason = ReapplyGenerationChanged
		s.datapath.rowsNotChecked()
	case s.reapplyPending:
		s.datapath.rowsNotChecked()
	default:
		if s.rowsPresentLocked() {
			return
		}
		slog.Warn("ingresssidecar: this sidecar's rows are missing from the shared eBPF maps, reapplying")
		s.reapplyPending = true
		reason = ReapplyRowsMissing
	}
	if s.generation == "" && !s.anyInstalledLocked() {
		s.generation = gen // nothing written yet, so nothing to reapply
		return
	}

	slog.Info("ingresssidecar: eBPF datapath changed, reapplying every VRF and route",
		"previous", s.generation, "current", gen, "retry", s.reapplyPending)
	if s.metrics != nil {
		s.metrics.Reapplies.Inc()
	}
	s.generation = gen
	ok := s.reapplyLocked()
	s.reapplyPending = !ok
	s.datapath.reapplied(reason, ok)
	s.datapath.rowsNotChecked() // rewritten, not read back yet
}

// rowsPresentLocked reports whether the shared eBPF maps still hold the rows of
// every VRF reapplyLocked would reapply. A failed read counts as present, for
// the same reason a failed generation read is not acted on, but is reported
// as an error. Callers must hold s.mu.
func (s *Store) rowsPresentLocked() bool {
	var tableIDs []uint32
	for _, v := range s.vrfs {
		if v.installed && v.absentSince.IsZero() && v.tableID != 0 {
			tableIDs = append(tableIDs, v.tableID)
		}
	}
	if len(tableIDs) == 0 {
		s.datapath.rowsNotChecked() // nothing to read back
		return true
	}
	present, err := s.backend.DatapathRowsPresent(tableIDs)
	switch {
	case err != nil:
		s.datapath.checked(CheckRegistrationRows, CheckError)
		slog.Debug("ingresssidecar: read back eBPF map rows", "err", err)
		return true
	case !present:
		s.datapath.checked(CheckRegistrationRows, CheckMissing)
	default:
		s.datapath.checked(CheckRegistrationRows, CheckOK)
	}
	return present
}

// reapplyLocked re-runs EnsureVRF for every installed VRF with a live route,
// then EnsureRoute for every installed route still desired, reporting whether
// all of them succeeded. State within its teardown grace period is left alone:
// reinstalling it would only extend the life of something already on its way
// out. Callers must hold s.mu.
func (s *Store) reapplyLocked() bool {
	ok := true
	failedVPCs := make(map[string]struct{})
	for vpc, v := range s.vrfs {
		if !v.installed || !v.absentSince.IsZero() {
			continue
		}
		tableID, err := s.backend.EnsureVRF(vpc)
		s.convergence.operation(OpReapplyVRF, err)
		if err != nil {
			s.countError("reapply_vrf")
			slog.Error("ingresssidecar: reapply VRF", "vpc", vpc, "error", err)
			failedVPCs[vpc] = struct{}{}
			ok = false
			continue
		}
		if tableID != v.tableID {
			slog.Warn("ingresssidecar: VRF table ID changed on reapply", "vpc", vpc,
				"previous", v.tableID, "current", tableID)
			v.tableID = tableID
		}
	}

	for key, r := range s.routes {
		if !r.installed || !r.absentSince.IsZero() {
			continue
		}
		if _, failed := failedVPCs[r.vpc]; failed {
			continue // already counted against this pass; retried with its VRF
		}
		v, found := s.vrfs[r.vpc]
		if !found {
			slog.Error("ingresssidecar: reapply found route with no tracked VRF", "key", key, "vpc", r.vpc)
			continue
		}
		err := s.backend.EnsureRoute(r.prefix, r.sid, v.tableID)
		s.convergence.operation(OpReapplyRoute, err)
		if err != nil {
			s.countError("reapply_route")
			slog.Error("ingresssidecar: reapply route", "key", key, "vpc", r.vpc, "error", err)
			ok = false
		}
	}
	return ok
}

// anyInstalledLocked reports whether this Store has written any VRF to the
// backend. Callers must hold s.mu.
func (s *Store) anyInstalledLocked() bool {
	for _, v := range s.vrfs {
		if v.installed {
			return true
		}
	}
	return false
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
