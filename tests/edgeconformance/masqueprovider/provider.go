// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/provider"
)

// Pod identifies the pod this process runs in.
type Pod struct {
	Namespace, Name, UID, Node, BootID string
	// RunAsUser and RunAsGroup own the packet devices this process opens.
	RunAsUser, RunAsGroup int64
}

// Provider is one fixture instance: it holds its EdgeInstance's lease, one
// PacketAccess attachment per service and one EdgeRoute per connector /96,
// and admits a connector's CONNECT-IP request only while all three are
// current. Its Client must read from the API server.
type Provider struct {
	Client client.Client
	Log    *slog.Logger
	Config *Config
	Pod    Pod
	Claims *claim.Instance
	Clock  claim.Clock
	// Renew is how often the lease is renewed.
	Renew time.Duration
	// OpenTUN opens an attachment's packet device as a nonblocking
	// descriptor.
	OpenTUN func(name string) (*os.File, error)

	instance *galacticv1alpha1.EdgeInstance

	mu         sync.Mutex
	lease      *claim.Lease
	services   map[string]*service
	connectors []*connector
	// deadline is the held lease's deadline on Clock, or zero; every packet
	// reads it, so forwarding stops at the deadline even while the
	// reconcile loop waits on the API.
	deadline  atomic.Int64
	sessionID atomic.Uint64
}

type service struct {
	cfg        Service
	attachment *galacticv1alpha1.EdgeAttachment
	// programmed identifies the host state the backend was opened on.
	programmed string
	backend    *connectip.TUNBackend
}

type connector struct {
	cfg    Connector
	svc    *service
	route  string
	epoch  int64
	active bool
	grants map[*grant]struct{}
	logged string
}

// forwarding reports whether the held lease allows packets now.
func (p *Provider) forwarding() bool { return int64(p.Clock()) < p.deadline.Load() }

func (p *Provider) setLease(l *claim.Lease) {
	p.lease = l
	if l == nil {
		p.deadline.Store(0)
		return
	}
	p.deadline.Store(int64(l.Deadline))
}

// Start registers the pod's EdgeInstance and sets up the service and
// connector state.
func (p *Provider) Start(ctx context.Context) error {
	inst, err := provider.CreateInstance(ctx, p.Client, provider.NewInstance(p.Pod.Namespace, p.Config.Provider,
		p.Pod.Name, p.Pod.UID, p.Pod.Node, p.Pod.BootID))
	if err != nil {
		return fmt.Errorf("register EdgeInstance: %w", err)
	}
	p.instance = inst
	p.services = map[string]*service{}
	for _, s := range p.Config.Services {
		p.services[s.Key()] = &service{cfg: s}
	}
	for _, c := range p.Config.Connectors {
		svc := p.services[c.Service]
		p.connectors = append(p.connectors, &connector{cfg: c, svc: svc,
			route: provider.RouteName(svc.cfg.VPCUID, c.Prefix), grants: map[*grant]struct{}{}})
	}
	p.Log.Info("instance registered", "instance", inst.Name)
	return nil
}

// Reconcile makes one pass: lease, then each attachment, then each route.
// It returns an error only when retrying cannot succeed.
func (p *Provider) Reconcile(ctx context.Context) error {
	if err := p.reconcileLease(ctx); err != nil {
		return err
	}
	for _, s := range p.Config.Services {
		if err := p.reconcileAttachment(ctx, p.services[s.Key()]); err != nil {
			if errors.Is(err, provider.ErrNameTaken) {
				return err
			}
			p.Log.Warn("attachment reconcile failed", "service", s.Name, "error", err)
		}
	}
	for _, c := range p.connectors {
		p.reconcileRoute(ctx, c)
	}
	return nil
}

func (p *Provider) reconcileLease(ctx context.Context) error {
	p.mu.Lock()
	l := p.lease
	p.mu.Unlock()
	now := p.Clock()
	if l != nil && !l.Valid(now) {
		p.Log.Warn("lease expired", "epoch", l.Epoch)
		p.loseLease()
		l = nil
	}
	if l == nil {
		got, err := p.Claims.Acquire(ctx, p.instance.Name)
		switch {
		case errors.Is(err, provider.ErrNameTaken):
			return err
		case err != nil:
			p.Log.Warn("lease not yet acquired", "reason", err)
			return nil
		}
		p.mu.Lock()
		p.setLease(&got)
		p.mu.Unlock()
		p.Log.Info("lease acquired", "epoch", got.Epoch)
		return nil
	}
	// A lease's deadline is its renewal's start plus the claim duration.
	if now < l.Deadline-p.Claims.Params.Duration+p.Renew {
		return nil
	}
	got, err := p.Claims.Renew(ctx, *l)
	switch {
	case errors.Is(err, claim.ErrLost):
		p.Log.Warn("lease lost", "epoch", l.Epoch, "reason", err)
		p.loseLease()
	case err != nil:
		p.Log.Warn("lease renewal failed; the lease holds until its deadline", "error", err)
	default:
		p.mu.Lock()
		p.setLease(&got)
		p.mu.Unlock()
	}
	return nil
}

// loseLease ends every session: every route claim was made under the lost
// epoch.
func (p *Provider) loseLease() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setLease(nil)
	for _, c := range p.connectors {
		p.deactivate(c, "lease lost")
	}
}

func (p *Provider) reconcileAttachment(ctx context.Context, s *service) error {
	name := provider.AttachmentName(s.cfg.UID, p.Pod.UID)
	var att galacticv1alpha1.EdgeAttachment
	err := p.Client.Get(ctx, client.ObjectKey{Namespace: p.Pod.Namespace, Name: name}, &att)
	switch {
	case apierrors.IsNotFound(err):
		p.stopServing(s, "attachment missing")
		created, err := provider.CreateAttachment(ctx, p.Client, p.attachmentRequest(s, name))
		if err != nil {
			return fmt.Errorf("request attachment %s: %w", name, err)
		}
		p.Log.Info("attachment requested", "attachment", created.Name, "service", s.cfg.Name)
		return nil
	case err != nil:
		return err
	}
	if att.Spec.PodUID != p.Pod.UID || att.Spec.ServiceRef.UID != s.cfg.UID {
		return fmt.Errorf("%w: EdgeAttachment %s", provider.ErrNameTaken, name)
	}
	// Admit reads the stored copy while setReady writes att.
	p.mu.Lock()
	s.attachment = att.DeepCopy()
	p.mu.Unlock()
	if !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed) ||
		att.DeletionTimestamp != nil {
		p.stopServing(s, "attachment not programmed")
		return p.setReady(ctx, &att, false, "NotProgrammed", "waiting for galactic-edge to program the attachment")
	}
	key := att.Status.HostLink + "/" + att.Status.PacketDevice + "/" + att.Status.Address
	p.mu.Lock()
	open := s.backend != nil && s.programmed == key
	p.mu.Unlock()
	if !open {
		p.stopServing(s, "attachment reprogrammed")
		if err := p.openBackend(s, att.Status.PacketDevice, key); err != nil {
			return p.setReady(ctx, &att, false, "DataPlaneFailed", err.Error())
		}
		p.Log.Info("serving attachment", "attachment", name, "device", att.Status.PacketDevice)
	}
	return p.setReady(ctx, &att, true, "Serving", "the provider is serving the attachment")
}

func (p *Provider) attachmentRequest(s *service, name string) *galacticv1alpha1.EdgeAttachment {
	return &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: p.Pod.Namespace, Name: name},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: p.Config.Provider},
			ServiceRef: galacticv1alpha1.EdgeServiceReference{Namespace: s.cfg.Namespace, Name: s.cfg.Name,
				UID: s.cfg.UID},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: p.instance.Name},
			PodUID:          p.Pod.UID,
			ContractVersion: "v1alpha1",
			Capabilities:    []galacticv1alpha1.EdgeCapability{{Name: "PacketAccess", Version: "v1"}},
			PacketDevice:    &galacticv1alpha1.EdgePacketDevice{Owner: p.Pod.RunAsUser, Group: p.Pod.RunAsGroup},
		},
	}
}

func (p *Provider) openBackend(s *service, device, key string) error {
	if device == "" {
		return errors.New("the attachment has no packet device")
	}
	f, err := p.OpenTUN(device)
	if err != nil {
		return err
	}
	b, err := connectip.NewTUNBackend(f, s.cfg.VPC)
	if err != nil {
		_ = f.Close()
		return err
	}
	p.mu.Lock()
	s.backend, s.programmed = b, key
	p.mu.Unlock()
	return nil
}

// stopServing ends s's sessions and closes its backend.
func (p *Provider) stopServing(s *service, reason string) {
	p.mu.Lock()
	b := s.backend
	s.backend, s.programmed = nil, ""
	for _, c := range p.connectors {
		if c.svc == s {
			p.deactivate(c, reason)
		}
	}
	p.mu.Unlock()
	if b != nil {
		_ = b.Close()
	}
}

// setReady writes the attachment's Ready condition, the only one a
// provider sets, when it differs.
func (p *Provider) setReady(ctx context.Context, att *galacticv1alpha1.EdgeAttachment, ready bool, reason,
	msg string) error {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	if c := meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady); c != nil &&
		c.Status == status && c.Reason == reason && c.ObservedGeneration == att.Generation {
		return nil
	}
	meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeAttachmentReady,
		Status: status, Reason: reason, Message: msg, ObservedGeneration: att.Generation})
	return p.Client.Status().Update(ctx, att)
}

// reconcileRoute claims c's /96 while the lease is held and c's backend is
// open, and activates c once core accepts the claim.
func (p *Provider) reconcileRoute(ctx context.Context, c *connector) {
	p.mu.Lock()
	l, att, open := p.lease, c.svc.attachment, c.svc.backend != nil
	p.mu.Unlock()
	if l == nil || att == nil || !open {
		return
	}
	var r galacticv1alpha1.EdgeRoute
	err := p.Client.Get(ctx, client.ObjectKey{Namespace: p.Pod.Namespace, Name: c.route}, &r)
	if apierrors.IsNotFound(err) {
		r = *provider.NewRoute(p.Pod.Namespace, p.Config.Provider, c.svc.cfg.VPCUID, c.cfg.Prefix)
		r.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{Attachment: att.Name, HolderPodUID: p.Pod.UID,
			HolderInstance: l.Key, InstanceEpoch: int64(l.Epoch), Epoch: 1}
		err = p.Client.Create(ctx, &r)
	} else if err == nil {
		err = provider.Claim(ctx, p.Client, &r, att.Name, p.Pod.UID, *l)
	}
	if err != nil {
		if !apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) {
			p.Log.Warn("route claim failed", "connector", c.cfg.ID, "error", err)
		}
		return
	}
	accepted := acceptedFor(&r, att.Name, l)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lease == nil || p.lease.Epoch != l.Epoch || c.svc.attachment == nil || c.svc.attachment.Name != att.Name {
		return
	}
	switch {
	case accepted && (!c.active || c.epoch != r.Spec.Claim.Epoch):
		p.deactivate(c, "claim epoch changed")
		c.active, c.epoch = true, r.Spec.Claim.Epoch
	case !accepted:
		p.deactivate(c, "route not accepted")
	}
	if state := fmt.Sprintf("accepted=%t epoch=%d", accepted, r.Spec.Claim.Epoch); state != c.logged {
		c.logged = state
		p.Log.Info("route", "connector", c.cfg.ID, "route", r.Name, "prefix", c.cfg.Prefix, "state", state)
	}
}

// acceptedFor reports whether core accepted the route's current claim for
// attachment under l and has not revoked or closed it.
func acceptedFor(r *galacticv1alpha1.EdgeRoute, attachment string, l *claim.Lease) bool {
	a, cl := r.Status.Accepted, r.Spec.Claim
	return a != nil && cl != nil && !cl.Released && a.Epoch == cl.Epoch && a.Attachment == attachment &&
		a.Instance == l.Key && a.InstanceEpoch == int64(l.Epoch) && r.Status.ClosedEpoch < cl.Epoch &&
		meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted)
}

// deactivate ends every session of c. The caller holds p.mu.
func (p *Provider) deactivate(c *connector, reason string) {
	if c.active || len(c.grants) > 0 {
		p.Log.Info("connector inactive", "connector", c.cfg.ID, "reason", reason)
	}
	c.active, c.epoch = false, 0
	for g := range c.grants {
		g.end()
		delete(c.grants, g)
	}
}

// Shutdown ends every session, then releases the routes, deletes the
// attachments and releases the lease, in that order, so a replacement takes
// nothing over while this instance still forwards.
func (p *Provider) Shutdown(ctx context.Context) error {
	p.Log.Info("shutting down")
	p.mu.Lock()
	l := p.lease
	p.setLease(nil)
	p.mu.Unlock()
	for _, s := range p.services {
		p.stopServing(s, "shutting down")
	}
	var errs []error
	if l != nil {
		for _, c := range p.connectors {
			if err := p.releaseRoute(ctx, c, *l); err != nil {
				errs = append(errs, fmt.Errorf("release route of %s: %w", c.cfg.ID, err))
			}
		}
	}
	for _, s := range p.services {
		if s.attachment == nil {
			continue
		}
		if err := p.Client.Delete(ctx, s.attachment); client.IgnoreNotFound(err) != nil {
			errs = append(errs, fmt.Errorf("delete attachment %s: %w", s.attachment.Name, err))
		}
	}
	if l != nil {
		if err := p.Claims.Release(ctx, *l); err != nil {
			errs = append(errs, fmt.Errorf("release lease: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (p *Provider) releaseRoute(ctx context.Context, c *connector, l claim.Lease) error {
	for range 5 {
		var r galacticv1alpha1.EdgeRoute
		err := p.Client.Get(ctx, client.ObjectKey{Namespace: p.Pod.Namespace, Name: c.route}, &r)
		if err != nil {
			return client.IgnoreNotFound(err)
		}
		err = provider.Release(ctx, p.Client, &r, l)
		if errors.Is(err, provider.ErrNotHolder) {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return err
		}
	}
	return errors.New("route kept changing")
}

// Admit implements connectip.Admission for the configured connectors.
func (p *Provider) Admit(_ context.Context, credential, vpc string) (connectip.Lease, error) {
	var c *connector
	for _, cand := range p.connectors {
		if subtle.ConstantTimeCompare([]byte(cand.cfg.Credential), []byte(credential)) == 1 {
			c = cand
		}
	}
	if c == nil {
		return nil, connectip.ErrUnauthenticated
	}
	if c.svc.cfg.VPC != vpc {
		return nil, connectip.ErrForbidden
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !c.active || p.lease == nil || c.svc.backend == nil || c.svc.attachment == nil || !p.forwarding() {
		return nil, fmt.Errorf("connector %s has no accepted route on a programmed attachment", c.cfg.ID)
	}
	g := &grant{
		p: p, c: c, done: make(chan struct{}),
		info: connectip.SessionInfo{
			ID: p.sessionID.Add(1), Principal: c.cfg.ID, VPC: vpc, Prefix: c.cfg.Prefix,
			Connector: c.cfg.ID, Attachment: c.svc.attachment.Name, Claim: c.route, Epoch: uint64(c.epoch),
		},
	}
	c.grants[g] = struct{}{}
	return g, nil
}

// grant is one admitted request's lease.
type grant struct {
	p       *Provider
	c       *connector
	info    connectip.SessionInfo
	done    chan struct{}
	endOnce sync.Once
}

func (g *grant) Info() connectip.SessionInfo { return g.info }
func (g *grant) Routes() []netip.Prefix      { return g.c.cfg.Routes }
func (g *grant) Done() <-chan struct{}       { return g.done }
func (g *grant) end()                        { g.endOnce.Do(func() { close(g.done) }) }

func (g *grant) Close() error {
	g.end()
	g.p.mu.Lock()
	delete(g.c.grants, g)
	g.p.mu.Unlock()
	return nil
}

// Open implements connectip.PacketBackend: it opens the session on the
// backend of the attachment admission named, and drops its packets once
// the lease's deadline passes.
func (p *Provider) Open(ctx context.Context, info connectip.SessionInfo) (connectip.BackendSession, error) {
	p.mu.Lock()
	var b *connectip.TUNBackend
	for _, s := range p.services {
		if s.attachment != nil && s.attachment.Name == info.Attachment {
			b = s.backend
		}
	}
	p.mu.Unlock()
	if b == nil {
		return nil, fmt.Errorf("attachment %s is not being served", info.Attachment)
	}
	s, err := b.Open(ctx, info)
	if err != nil {
		return nil, err
	}
	return &gatedSession{BackendSession: s, allow: p.forwarding}, nil
}

var errExpired = errors.New("the instance's lease has expired")

// gatedSession forwards packets only while allow reports true.
type gatedSession struct {
	connectip.BackendSession
	allow func() bool
}

func (s *gatedSession) WritePacket(pkt []byte) error {
	if !s.allow() {
		return errExpired
	}
	return s.BackendSession.WritePacket(pkt)
}

func (s *gatedSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	n, err := s.BackendSession.ReadPacket(ctx, buf)
	if err == nil && !s.allow() {
		return 0, errExpired
	}
	return n, err
}

// newHolderID returns a unique holder identity for this process.
func newHolderID() string { return rand.Text() }
