// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package masque

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/provider"
	"go.datum.net/galactic/internal/edge/timing"
)

// ContractVersion is the provider contract version the adapter requests.
const ContractVersion = "v1alpha1"

// Capability names the adapter uses.
const (
	PacketAccess       = "PacketAccess"
	PrefixReachability = "PrefixReachability"
)

// Capabilities are what the MASQUE EdgeProvider lists and each of its
// EdgeServices grants, all at version v1: PacketAccess for the attachment's
// packet device and PrefixReachability for the connector routes. An
// attachment requests only PacketAccess; core accepts a route only when its
// service grants PrefixReachability.
var Capabilities = []string{PacketAccess, PrefixReachability}

// Pod identifies the pod an Adapter runs in.
type Pod struct {
	Namespace, Name, UID, Node, BootID string
	// RunAsUser and RunAsGroup own the packet devices the adapter opens.
	RunAsUser, RunAsGroup int64
}

// Config configures an Adapter.
type Config struct {
	// Client must read from the API server, not a cache, and must
	// authenticate as the pod's ServiceAccount with its pod-bound token.
	Client client.Client
	// Provider is the EdgeProvider the pod runs as.
	Provider string
	Pod      Pod
	// Authorizer issues the grant of each request.
	Authorizer Authorizer
	// Claims holds the instance's lease. Its Store must be a
	// provider.InstanceStore in Pod.Namespace and its Clock is the clock
	// every lease deadline is read on.
	Claims *claim.Instance
	// OpenDevice opens an existing TUN device in the pod as a nonblocking
	// descriptor without packet-information headers.
	OpenDevice func(name string) (*os.File, error)
	// Now is the wall clock grants are checked against. Nil means
	// time.Now.
	Now func() time.Time
	// Log is optional and defaults to slog.Default().
	Log *slog.Logger
	// Renew is how often the lease is renewed. Zero means
	// timing.RenewInterval.
	Renew time.Duration
	// Poll is how often the adapter rechecks its attachments and routes,
	// and how often a request waits between reads while they are prepared.
	// Zero means one second.
	Poll time.Duration
	// AuthorizeTimeout bounds each Authorizer.Authorize call, the part of
	// admission an unauthenticated client can start. Zero means 3 seconds.
	AuthorizeTimeout time.Duration
	// Prepare bounds how long a request waits for its attachment to be
	// programmed and its route accepted. Zero means 30 seconds.
	Prepare time.Duration
	// Idle is how long an attachment with no request is kept before it is
	// deleted. Zero means 30 seconds.
	Idle time.Duration
	// Refresh is how often each open request's grant is refreshed. Zero
	// means timing.RenewInterval.
	Refresh time.Duration
}

// Adapter is one provider pod's connectip.Admission and
// connectip.PacketBackend. Start it, run Run until shutdown, then call
// Shutdown after the transports have ended every request.
type Adapter struct {
	cfg  Config
	log  *slog.Logger
	inst *galacticv1alpha1.EdgeInstance

	// lease is the held instance lease, or nil. deadline is its deadline
	// on cfg.Claims.Clock, or zero; every packet reads it.
	lease    atomic.Pointer[claim.Lease]
	deadline atomic.Int64
	nextID   atomic.Uint64

	// stop is cancelled when Shutdown starts, ending every preparation in
	// flight; admitting counts the requests between their reservation and
	// their registration or refusal.
	stop       context.Context
	cancelStop context.CancelFunc
	admitting  sync.WaitGroup

	mu      sync.Mutex
	closing bool
	// pending holds the connectors whose request is being prepared.
	pending map[string]bool
	// revokeSeq counts Revoke calls and revokedAt holds each connector's
	// latest, so an admission that began before it is refused.
	revokeSeq   uint64
	revokedAt   map[string]uint64
	attachments map[string]*attachment
	routes      map[string]*route
	sessions    map[uint64]*session
}

// New validates cfg and returns an Adapter.
func New(cfg Config) (*Adapter, error) {
	switch {
	case cfg.Client == nil || cfg.Authorizer == nil || cfg.Claims == nil || cfg.OpenDevice == nil:
		return nil, errors.New("client, authorizer, claims and device opener are required")
	case cfg.Provider == "":
		return nil, errors.New("provider is required")
	case cfg.Pod.Namespace == "" || cfg.Pod.Name == "" || cfg.Pod.UID == "" || cfg.Pod.Node == "":
		return nil, errors.New("pod namespace, name, UID and node are required")
	case cfg.Claims.Clock == nil:
		return nil, errors.New("claims clock is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Renew == 0 {
		cfg.Renew = timing.RenewInterval
	}
	if cfg.Poll == 0 {
		cfg.Poll = time.Second
	}
	if cfg.AuthorizeTimeout == 0 {
		cfg.AuthorizeTimeout = 3 * time.Second
	}
	if cfg.Prepare == 0 {
		cfg.Prepare = 30 * time.Second
	}
	if cfg.Idle == 0 {
		cfg.Idle = 30 * time.Second
	}
	if cfg.Refresh == 0 {
		cfg.Refresh = timing.RenewInterval
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	a := &Adapter{
		cfg: cfg, log: log, attachments: map[string]*attachment{}, routes: map[string]*route{},
		sessions: map[uint64]*session{}, pending: map[string]bool{}, revokedAt: map[string]uint64{},
	}
	a.stop, a.cancelStop = context.WithCancel(context.Background())
	return a, nil
}

// Start registers the pod's EdgeInstance and adopts the attachments an
// earlier process of the same pod left behind. An adopted attachment is
// idle: it is served again when a request names its service, and deleted
// otherwise. Start restores no forwarding permission: every route is
// claimed again under the lease this process acquires.
func (a *Adapter) Start(ctx context.Context) error {
	p := a.cfg.Pod
	inst, err := provider.CreateInstance(ctx, a.cfg.Client,
		provider.NewInstance(p.Namespace, a.cfg.Provider, p.Name, p.UID, p.Node, p.BootID))
	if err != nil {
		return fmt.Errorf("register EdgeInstance: %w", err)
	}
	a.inst = inst
	var list galacticv1alpha1.EdgeAttachmentList
	if err := a.cfg.Client.List(ctx, &list, client.InNamespace(p.Namespace)); err != nil {
		return fmt.Errorf("list EdgeAttachments: %w", err)
	}
	now := a.cfg.Claims.Clock()
	for i := range list.Items {
		att := &list.Items[i]
		ref := att.Spec.ServiceRef
		if att.Spec.PodUID != p.UID || att.Name != provider.AttachmentName(ref.UID, p.UID) {
			continue
		}
		a.mu.Lock()
		a.attachments[ref.UID] = &attachment{name: att.Name, uid: att.UID, idleSince: now, prep: newPrepLock(),
			svc: ServiceRef{Namespace: ref.Namespace, Name: ref.Name, UID: ref.UID}}
		a.mu.Unlock()
		// No device is open on it in this process until a request needs it.
		// One being deleted waits for its release instead.
		if att.DeletionTimestamp == nil {
			_ = a.setReady(ctx, att, false, "NotServing", "adopted by a restarted provider process")
		}
		a.log.Info("adopted attachment", "attachment", att.Name)
	}
	a.log.Info("instance registered", "instanceName", inst.Name)
	return nil
}

// Run renews the instance's lease and rechecks the adapter's attachments and
// routes until ctx ends. Renewal runs on its own worker, so a slow check
// never delays it. Run returns early only when the instance's lease can
// never be held, as when its name is taken.
func (a *Adapter) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	renewErr := make(chan error, 1)
	go func() {
		err := a.renewLoop(ctx)
		cancel()
		renewErr <- err
	}()
	t := time.NewTicker(a.cfg.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return <-renewErr
		case <-t.C:
			a.check(ctx)
		}
	}
}

func (a *Adapter) renewLoop(ctx context.Context) error {
	t := time.NewTicker(min(a.cfg.Renew/5, time.Second))
	defer t.Stop()
	for {
		if err := a.renew(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// renew acquires the lease when none is held and renews it when due. It
// does nothing once Shutdown has started, so a released lease is never
// taken again.
func (a *Adapter) renew(ctx context.Context) error {
	a.mu.Lock()
	closing := a.closing
	a.mu.Unlock()
	if closing {
		return nil
	}
	in := a.cfg.Claims
	l := a.lease.Load()
	now := in.Clock()
	if l != nil && !l.Valid(now) {
		a.loseLease("lease expired")
		l = nil
	}
	if l == nil {
		got, err := in.Acquire(ctx, a.inst.Name)
		switch {
		case errors.Is(err, provider.ErrNameTaken):
			return err
		case err != nil:
			a.log.Debug("lease not yet acquired", "reason", err)
			return nil
		}
		a.setLease(&got)
		a.log.Info("lease acquired", "epoch", got.Epoch)
		return nil
	}
	if now < l.Deadline-in.Params.Duration+a.cfg.Renew {
		return nil
	}
	got, err := in.Renew(ctx, *l)
	switch {
	case errors.Is(err, claim.ErrLost):
		a.loseLease(err.Error())
	case err != nil:
		a.log.Warn("lease renewal failed; the lease holds until its deadline", "error", err)
	default:
		a.setLease(&got)
	}
	return nil
}

func (a *Adapter) setLease(l *claim.Lease) {
	if l == nil {
		a.deadline.Store(0)
	} else {
		a.deadline.Store(int64(l.Deadline))
	}
	a.lease.Store(l)
}

// heldLease returns the lease while it is valid.
func (a *Adapter) heldLease() (claim.Lease, bool) {
	l := a.lease.Load()
	if l == nil || !l.Valid(a.cfg.Claims.Clock()) {
		return claim.Lease{}, false
	}
	return *l, true
}

// loseLease ends every request: each route was claimed under the lost
// epoch.
func (a *Adapter) loseLease(reason string) {
	a.setLease(nil)
	a.log.Warn("lease lost", "reason", reason)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.routes {
		a.deactivate(r, reason)
	}
	for _, s := range a.sessions {
		s.end(reason)
	}
}

// quiesceTimeout bounds how long a replacement waits for the request it
// replaces to stop its packet I/O and close.
const quiesceTimeout = time.Second

// Admit implements connectip.Admission. It returns the Authorizer's
// connectip.ErrUnauthenticated or connectip.ErrForbidden, and ErrUnavailable
// when the grant is valid but the connector cannot forward now.
//
// A request of a connector that already has one open replaces it once
// authorized and prepared: the open request ends, and the new one is
// registered only after the old one closed, so the connector never has two
// forwarding requests. The attachment and route stay held across the
// handoff when the grant names the same service. A request arriving while
// another of the same connector is being admitted is refused as
// unavailable.
func (a *Adapter) Admit(ctx context.Context, credential, vpc string) (connectip.Lease, error) {
	a.mu.Lock()
	began := a.revokeSeq
	a.mu.Unlock()
	actx, stopAuthorize := context.WithTimeout(ctx, a.cfg.AuthorizeTimeout)
	g, err := a.cfg.Authorizer.Authorize(actx, credential, vpc)
	stopAuthorize()
	if err != nil {
		return nil, err
	}
	if err := g.validate(vpc, a.cfg.Now()); err != nil {
		return nil, fmt.Errorf("%w: connector %s: %w", ErrUnavailable, g.Connector, err)
	}
	if _, ok := a.heldLease(); !ok {
		return nil, fmt.Errorf("%w: the instance holds no lease", ErrUnavailable)
	}
	a.mu.Lock()
	closing, busy := a.closing, a.pending[g.Connector]
	if !closing && !busy {
		a.pending[g.Connector] = true
		a.admitting.Add(1)
	}
	a.mu.Unlock()
	switch {
	case closing:
		return nil, fmt.Errorf("%w: the provider is shutting down", ErrUnavailable)
	case busy:
		return nil, fmt.Errorf("%w: connector %s already has a request being admitted", ErrUnavailable,
			g.Connector)
	}
	// The connector's reservation ends once its request is registered or
	// refused.
	defer func() {
		a.mu.Lock()
		delete(a.pending, g.Connector)
		a.mu.Unlock()
		a.admitting.Done()
	}()

	ctx, cancel := context.WithTimeout(ctx, a.cfg.Prepare)
	defer cancel()
	defer context.AfterFunc(a.stop, cancel)()
	att, err := a.acquireAttachment(ctx, &g)
	if err != nil {
		return nil, fmt.Errorf("%w: connector %s: %w", ErrUnavailable, g.Connector, err)
	}
	rt, err := a.acquireRoute(ctx, &g, att)
	if err != nil {
		a.releaseAttachment(att)
		return nil, fmt.Errorf("%w: connector %s: %w", ErrUnavailable, g.Connector, err)
	}
	if err := a.replace(&g); err != nil {
		rctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer cancel()
		a.releaseRoute(rctx, rt)
		a.releaseAttachment(att)
		return nil, fmt.Errorf("%w: connector %s: %w", ErrUnavailable, g.Connector, err)
	}
	return a.newSession(&g, att, rt, began)
}

// replace ends the open requests of g's connector and waits, up to
// quiesceTimeout, for each to close: its packet I/O stopped, its device
// registration and queued packets discarded and its references dropped.
// A request that does not close in time fails the replacement and has its
// grant retired, since it may still hold a packet in flight; the connector
// then forwards through neither request.
// The wait has its own bound rather than the request's, so a request that
// spent most of its preparation time still gives the old one the full
// quiesce period.
func (a *Adapter) replace(g *Grant) error {
	a.mu.Lock()
	var old []*session
	for _, s := range a.sessions {
		if s.grant.Connector == g.Connector {
			old = append(old, s)
		}
	}
	a.mu.Unlock()
	if len(old) == 0 {
		return nil
	}
	t := time.NewTimer(quiesceTimeout)
	defer t.Stop()
	for _, s := range old {
		s.end("replaced")
		a.log.Info("replacing request", "session", s.info.ID, "connector", g.Connector)
	}
	for _, s := range old {
		select {
		case <-s.closed:
		case <-t.C:
			rctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
			defer cancel()
			if err := a.cfg.Authorizer.Retire(rctx, s.grant); err != nil {
				a.log.Warn("could not retire the grant of a request that did not stop", "session", s.info.ID,
					"connector", g.Connector, "error", err)
			}
			return fmt.Errorf("request %d did not stop within %v", s.info.ID, quiesceTimeout)
		case <-a.stop.Done():
			return fmt.Errorf("waiting for request %d to stop: the provider is shutting down", s.info.ID)
		}
	}
	return nil
}

// Revoke ends the open requests of connector, as when its authority
// reports the connector's grant revoked, and refuses the connector's
// admissions already under way. Each request's transport then closes it and
// releases what it held. It does not wait.
func (a *Adapter) Revoke(connector string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revokeSeq++
	a.revokedAt[connector] = a.revokeSeq
	for _, s := range a.sessions {
		if s.grant.Connector == connector {
			s.end("revoked")
		}
	}
}

// Ready reports whether the adapter can admit a request now: it holds a
// valid instance lease and Shutdown has not started. A readiness probe reads
// it, so a pod without its lease takes no new clients.
func (a *Adapter) Ready() bool {
	_, held := a.heldLease()
	return held && !a.isClosing()
}

// isClosing reports whether Shutdown has started.
func (a *Adapter) isClosing() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closing
}

// Shutdown stops admitting requests and waits, bounded by ctx, for those
// still being prepared to give up. It then ends every request, releases the
// routes, deletes the attachments and releases the lease, in that order, so
// that nothing is taken over while this pod still forwards. Call it after
// Run returned and the transports stopped serving.
func (a *Adapter) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	// Requests still being prepared stop, so that what they created is in
	// the snapshot below.
	a.cancelStop()
	var errs []error
	admitted := make(chan struct{})
	go func() {
		a.admitting.Wait()
		close(admitted)
	}()
	select {
	case <-admitted:
	case <-ctx.Done():
		errs = append(errs, fmt.Errorf("requests still being admitted: %w", context.Cause(ctx)))
	}
	a.mu.Lock()
	sessions := make([]*session, 0, len(a.sessions))
	for _, s := range a.sessions {
		sessions = append(sessions, s)
	}
	a.mu.Unlock()
	l := a.lease.Load()
	a.setLease(nil)
	for _, s := range sessions {
		s.close(ctx)
	}
	a.mu.Lock()
	routes := make([]*route, 0, len(a.routes))
	for _, r := range a.routes {
		routes = append(routes, r)
	}
	atts := make([]*attachment, 0, len(a.attachments))
	for _, e := range a.attachments {
		atts = append(atts, e)
	}
	a.mu.Unlock()
	for _, r := range routes {
		if err := r.prep.lock(ctx); err != nil {
			errs = append(errs, fmt.Errorf("release route %s: %w", r.name, err))
			continue
		}
		if err := a.releaseClaim(ctx, r); err != nil {
			errs = append(errs, err)
		}
		r.prep.unlock()
	}
	for _, e := range atts {
		if err := e.prep.lock(ctx); err != nil {
			errs = append(errs, fmt.Errorf("delete attachment %s: %w", e.name, err))
			continue
		}
		a.closeAttachment(e, "shutting down")
		if err := a.deleteAttachment(ctx, e); err != nil {
			errs = append(errs, err)
		}
		e.prep.unlock()
	}
	if l != nil {
		if err := a.cfg.Claims.Release(ctx, *l); err != nil {
			errs = append(errs, fmt.Errorf("release lease: %w", err))
		}
	}
	return errors.Join(errs...)
}

// check ends the requests whose attachment or route is no longer current
// and deletes attachments idle for longer than cfg.Idle.
func (a *Adapter) check(ctx context.Context) {
	a.mu.Lock()
	atts := make([]*attachment, 0, len(a.attachments))
	for _, e := range a.attachments {
		atts = append(atts, e)
	}
	routes := make([]*route, 0, len(a.routes))
	for _, r := range a.routes {
		if r.refs > 0 && r.active {
			routes = append(routes, r)
		}
	}
	a.mu.Unlock()
	for _, e := range atts {
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		a.checkAttachment(cctx, e)
		cancel()
	}
	for _, r := range routes {
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		a.checkRoute(cctx, r)
		cancel()
	}
}

// checkTimeout bounds the API calls of one attachment's or route's check,
// so a stalled call delays the others by at most that long.
const checkTimeout = 5 * time.Second

// wait sleeps for one poll interval or until ctx ends.
func (a *Adapter) wait(ctx context.Context, state string) error {
	t := time.NewTimer(a.cfg.Poll)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("%s: %w", state, context.Cause(ctx))
	case <-t.C:
		return nil
	}
}
