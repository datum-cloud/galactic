// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package provider runs one Galactic Edge provider instance through the
// contract's five steps: it registers its EdgeInstance, holds the instance's
// lease, requests an EdgeAttachment for each configured EdgeService, serves
// each attachment once galactic-edge has programmed it and reports Ready,
// claims the route of each configured prefix while its lease is valid, and
// on shutdown stops forwarding before releasing its claims, attachments and
// lease.
package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/datum-cloud/galactic/examples/edge-provider/internal/config"
	"github.com/datum-cloud/galactic/examples/edge-provider/internal/dataplane"
	"github.com/datum-cloud/galactic/examples/edge-provider/internal/lease"
	"github.com/datum-cloud/galactic/examples/edge-provider/internal/route"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// Pod identifies the pod this process runs in, from the downward API.
type Pod struct {
	Namespace string
	Name      string
	UID       string
	Node      string
	// BootID is the node's boot ID, /proc/sys/kernel/random/boot_id.
	BootID string
	// UID and GID own the packet devices this process opens.
	RunAsUser  int64
	RunAsGroup int64
}

// InstanceName is the derived name of the pod's EdgeInstance and its Lease.
func InstanceName(podUID string) string { return "ei-" + podUID }

// AttachmentName is the derived name of the pod's EdgeAttachment to the
// EdgeService with serviceUID.
func AttachmentName(podUID, serviceUID string) string { return "ea-" + podUID + "-" + serviceUID }

// ErrNameTaken is returned when a derived name is held by an object that
// names another pod, provider or service.
var ErrNameTaken = errors.New("provider: name held by another pod's object")

// Provider is one instance. Its Client must read from the API server.
type Provider struct {
	Client client.Client
	Log    *slog.Logger
	Config *config.Config
	Pod    Pod
	Clock  lease.Clock
	Params lease.Params
	// Tick is how often the instance reconciles; at most Params.Renew.
	Tick time.Duration
	// RetryAfter is how long a refused or deleted attachment waits before
	// it is requested again.
	RetryAfter time.Duration
	// Echo and TUN open the data planes; nil uses package dataplane.
	Echo func(ctx context.Context, log *slog.Logger, vrf string, addr netip.Addr, port uint16,
		identity string) (dataplane.Server, error)
	TUN func(log *slog.Logger, device, identity string, allow func() bool) (dataplane.Server, error)

	instance *galacticv1alpha1.EdgeInstance
	holder   *lease.Holder
	lease    *lease.Lease
	services []*service
	// deadline is the held lease's deadline on Clock, or zero. The packet
	// devices read it on every packet, so they stop answering at the
	// deadline even while the reconcile loop waits on the API.
	deadline atomic.Int64
}

// forwarding reports whether the lease allows forwarding now.
func (p *Provider) forwarding() bool { return int64(p.Clock()) < p.deadline.Load() }

// setLease records l as held, or nothing held when l is nil.
func (p *Provider) setLease(l *lease.Lease) {
	p.lease = l
	if l == nil {
		p.deadline.Store(0)
		return
	}
	p.deadline.Store(int64(l.Deadline))
}

// service is the instance's state for one EdgeService.
type service struct {
	cfg        config.Service
	attachment *galacticv1alpha1.EdgeAttachment
	retryAt    time.Duration
	refusal    string
	// programmed identifies the host state the data planes were opened
	// on, so they are reopened when galactic-edge reprograms it.
	programmed string
	echo, tun  dataplane.Server
	routes     map[netip.Prefix]string
}

// Run registers the instance and reconciles until ctx is done, then shuts
// down within the shutdown context's deadline. Closing freeze stops every
// API write and renewal while the data planes keep answering, as a provider
// whose control loop hung would; Run then waits for ctx without shutting
// down.
func (p *Provider) Run(ctx context.Context, shutdown func() (context.Context, context.CancelFunc),
	freeze <-chan struct{}) error {
	if p.Echo == nil {
		p.Echo = dataplane.Echo
	}
	if p.TUN == nil {
		p.TUN = dataplane.TUN
	}
	inst, err := p.register(ctx)
	if err != nil {
		return err
	}
	p.instance = inst
	p.holder = &lease.Holder{Client: p.Client, Instance: inst, ID: lease.NewID(), Clock: p.Clock, Params: p.Params}
	p.Log.Info("instance registered", "instance", inst.Name, "holder", p.holder.ID)
	for _, s := range p.Config.Services {
		p.services = append(p.services, &service{cfg: s, routes: map[netip.Prefix]string{}})
	}
	t := time.NewTicker(p.Tick)
	defer t.Stop()
	for {
		if err := p.reconcile(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			sctx, cancel := shutdown()
			defer cancel()
			return p.shutdown(sctx)
		case <-freeze:
			p.Log.Warn("frozen: no further renewals or API writes; data planes keep answering")
			<-ctx.Done()
			return nil
		case <-t.C:
		}
	}
}

// register creates the pod's EdgeInstance, or reads back the one a retried
// create left.
func (p *Provider) register(ctx context.Context) (*galacticv1alpha1.EdgeInstance, error) {
	inst := &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: p.Pod.Namespace, Name: InstanceName(p.Pod.UID)},
		Spec: galacticv1alpha1.EdgeInstanceSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: p.Config.Provider},
			PodName:     p.Pod.Name, PodUID: p.Pod.UID, NodeName: p.Pod.Node, BootID: p.Pod.BootID,
		},
	}
	err := p.Client.Create(ctx, inst)
	if err == nil {
		return inst, nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("create EdgeInstance %s: %w", inst.Name, err)
	}
	var cur galacticv1alpha1.EdgeInstance
	if err := p.Client.Get(ctx, client.ObjectKeyFromObject(inst), &cur); err != nil {
		return nil, err
	}
	if cur.Spec.PodUID != p.Pod.UID || cur.Spec.ProviderRef.Name != p.Config.Provider {
		return nil, fmt.Errorf("%w: EdgeInstance %s names pod %s of provider %s", ErrNameTaken, cur.Name,
			cur.Spec.PodUID, cur.Spec.ProviderRef.Name)
	}
	return &cur, nil
}

func (p *Provider) reconcile(ctx context.Context) error {
	if err := p.reconcileLease(ctx); err != nil {
		return err
	}
	for _, s := range p.services {
		if err := p.reconcileAttachment(ctx, s); err != nil {
			if errors.Is(err, ErrNameTaken) {
				return err
			}
			p.Log.Warn("attachment reconcile failed", "service", s.cfg.Name, "error", err)
		}
		p.reconcileRoutes(ctx, s)
	}
	return nil
}

// reconcileLease acquires the lease while it is not held, renews it every
// renewal interval, and stops forwarding the moment it is lost or expires.
func (p *Provider) reconcileLease(ctx context.Context) error {
	now := p.Clock()
	if p.lease != nil && !p.lease.Valid(now) {
		p.Log.Warn("lease expired", "epoch", p.lease.Epoch)
		p.loseLease()
	}
	if p.lease == nil {
		l, err := p.holder.Acquire(ctx)
		switch {
		case errors.Is(err, lease.ErrNameTaken):
			return err
		case err != nil:
			p.Log.Debug("lease not yet acquired", "reason", err)
			return nil
		}
		p.setLease(&l)
		p.Log.Info("lease acquired", "epoch", l.Epoch, "incarnation", l.Incarnation)
		return nil
	}
	if now-p.lease.RenewStart < p.Params.Renew {
		return nil
	}
	l, err := p.holder.Renew(ctx, *p.lease)
	switch {
	case errors.Is(err, lease.ErrLost):
		p.Log.Warn("lease lost", "epoch", p.lease.Epoch, "reason", err)
		p.loseLease()
	case err != nil:
		p.Log.Warn("lease renewal failed; the lease holds until its deadline", "error", err)
	default:
		p.setLease(&l)
	}
	return nil
}

// loseLease stops forwarding every prefix: the routes' claims are held
// under the lost epoch.
func (p *Provider) loseLease() {
	p.setLease(nil)
	for _, s := range p.services {
		closeServer(&s.tun)
		clear(s.routes)
	}
}

func (p *Provider) identity(s *service) string {
	return p.Config.Provider + "/" + p.Pod.Name + "/" + s.cfg.Name
}

func (p *Provider) reconcileAttachment(ctx context.Context, s *service) error {
	name := AttachmentName(p.Pod.UID, s.cfg.UID)
	var att galacticv1alpha1.EdgeAttachment
	err := p.Client.Get(ctx, client.ObjectKey{Namespace: p.Pod.Namespace, Name: name}, &att)
	switch {
	case apierrors.IsNotFound(err):
		if s.attachment != nil {
			p.Log.Warn("attachment deleted", "attachment", name)
			p.stopServing(s)
			s.attachment = nil
			s.retryAt = p.Clock() + p.RetryAfter
		}
		if p.Clock() < s.retryAt {
			return nil
		}
		return p.request(ctx, s, name)
	case err != nil:
		return err
	}
	if att.Spec.PodUID != p.Pod.UID || att.Spec.ServiceRef.UID != s.cfg.UID {
		return fmt.Errorf("%w: EdgeAttachment %s", ErrNameTaken, name)
	}
	s.attachment = &att
	if c := meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted); c != nil &&
		c.Status == metav1.ConditionFalse && s.refusal != c.Reason {
		s.refusal = c.Reason
		p.Log.Warn("attachment refused", "attachment", name, "reason", c.Reason, "message", c.Message)
	}
	programmed := meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed)
	if !programmed || att.DeletionTimestamp != nil {
		p.stopServing(s)
		return p.setReady(ctx, &att, false, "NotProgrammed", "waiting for galactic-edge to program the attachment")
	}
	key := att.Status.HostLink + "/" + att.Status.PodVRF + "/" + att.Status.PacketDevice + "/" + att.Status.Address
	if key != s.programmed {
		p.stopServing(s)
		if err := p.serve(ctx, s, &att); err != nil {
			p.stopServing(s)
			return p.setReady(ctx, &att, false, "DataPlaneFailed", err.Error())
		}
		s.programmed = key
		p.Log.Info("serving attachment", "attachment", name, "address", att.Status.Address,
			"vrf", att.Status.PodVRF, "device", att.Status.PacketDevice)
	}
	// The packet device answers only addresses in claimed prefixes, so it
	// is open only while the lease is held.
	if s.cfg.Has(config.PacketAccess) && p.lease != nil && s.tun == nil {
		if s.tun, err = p.TUN(p.Log, att.Status.PacketDevice, p.identity(s), p.forwarding); err != nil {
			p.stopServing(s)
			return p.setReady(ctx, &att, false, "DataPlaneFailed", err.Error())
		}
	}
	if s.cfg.Has(config.PacketAccess) && s.tun == nil {
		return p.setReady(ctx, &att, false, "AwaitingLease", "the packet device opens once the instance holds its lease")
	}
	return p.setReady(ctx, &att, true, "Serving", "the provider is serving the attachment")
}

// request creates the attachment for s.
func (p *Provider) request(ctx context.Context, s *service, name string) error {
	contract, version := config.ContractVersion, config.CapabilityVersion
	if s.cfg.ContractVersion != "" {
		contract = s.cfg.ContractVersion
	}
	if s.cfg.CapabilityVersion != "" {
		version = s.cfg.CapabilityVersion
	}
	att := &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: p.Pod.Namespace, Name: name},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: p.Config.Provider},
			ServiceRef: galacticv1alpha1.EdgeServiceReference{Namespace: s.cfg.Namespace, Name: s.cfg.Name,
				UID: s.cfg.UID},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: p.instance.Name},
			PodUID:          p.Pod.UID,
			ContractVersion: contract,
		},
	}
	for _, c := range s.cfg.Capabilities {
		att.Spec.Capabilities = append(att.Spec.Capabilities, galacticv1alpha1.EdgeCapability{Name: c, Version: version})
	}
	if s.cfg.Has(config.PacketAccess) {
		att.Spec.PacketDevice = &galacticv1alpha1.EdgePacketDevice{Owner: p.Pod.RunAsUser, Group: p.Pod.RunAsGroup}
	}
	if err := p.Client.Create(ctx, att); err != nil && !apierrors.IsAlreadyExists(err) {
		s.retryAt = p.Clock() + p.RetryAfter
		return fmt.Errorf("request attachment %s: %w", name, err)
	}
	p.Log.Info("attachment requested", "attachment", name, "service", s.cfg.Namespace+"/"+s.cfg.Name)
	return nil
}

// serve opens s's echo socket on the programmed attachment and checks its
// packet device is reported.
func (p *Provider) serve(ctx context.Context, s *service, att *galacticv1alpha1.EdgeAttachment) error {
	addr, err := netip.ParseAddr(att.Status.Address)
	if err != nil {
		return fmt.Errorf("attachment address %q: %w", att.Status.Address, err)
	}
	if s.cfg.Has(config.SocketAccess) {
		if s.echo, err = p.Echo(ctx, p.Log, att.Status.PodVRF, addr, p.Config.Port, p.identity(s)); err != nil {
			return err
		}
	}
	if s.cfg.Has(config.PacketAccess) {
		if att.Status.PacketDevice == "" {
			return errors.New("the attachment has no packet device")
		}
	}
	return nil
}

func (p *Provider) stopServing(s *service) {
	closeServer(&s.tun)
	closeServer(&s.echo)
	s.programmed = ""
	clear(s.routes)
}

func closeServer(s *dataplane.Server) {
	if *s != nil {
		_ = (*s).Close()
		*s = nil
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

// reconcileRoutes claims every prefix of s while the lease is held and s's
// packet device is open.
func (p *Provider) reconcileRoutes(ctx context.Context, s *service) {
	if p.lease == nil || s.tun == nil || s.attachment == nil {
		return
	}
	h := p.holderFor(s)
	for _, prefix := range s.cfg.Prefixes {
		r, err := route.Claim(ctx, p.Client, p.Pod.Namespace, p.Config.Provider, s.cfg.VPCUID, prefix, h)
		if err != nil {
			if !apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) {
				p.Log.Warn("route claim failed", "prefix", prefix, "error", err)
			}
			continue
		}
		state := "pending"
		if route.Accepted(r, h) {
			state = "accepted"
		} else if c := meta.FindStatusCondition(r.Status.Conditions, galacticv1alpha1.EdgeRouteClaimed); c != nil &&
			r.Status.Accepted != nil && c.Status == metav1.ConditionFalse {
			state = "refused: " + c.Reason
		}
		if s.routes[prefix] != state {
			s.routes[prefix] = state
			p.Log.Info("route", "prefix", prefix, "route", r.Name, "state", state, "epoch", r.Spec.Claim.Epoch)
		}
	}
}

func (p *Provider) holderFor(s *service) route.Holder {
	return route.Holder{Attachment: s.attachment.Name, PodUID: p.Pod.UID, Instance: p.instance.Name,
		InstanceEpoch: int64(p.lease.Epoch)}
}

// shutdown stops forwarding, then releases the routes, deletes the
// attachments and releases the lease, in that order, so another instance
// takes nothing over while this one still forwards.
func (p *Provider) shutdown(ctx context.Context) error {
	p.Log.Info("shutting down")
	var errs []error
	for _, s := range p.services {
		closeServer(&s.tun)
	}
	for _, s := range p.services {
		if p.lease == nil || s.attachment == nil {
			continue
		}
		h := p.holderFor(s)
		for _, prefix := range s.cfg.Prefixes {
			if err := route.Release(ctx, p.Client, p.Pod.Namespace, s.cfg.VPCUID, prefix, h); err != nil {
				errs = append(errs, fmt.Errorf("release route of %s: %w", prefix, err))
			}
		}
	}
	for _, s := range p.services {
		p.stopServing(s)
		if s.attachment == nil {
			continue
		}
		if err := p.Client.Delete(ctx, s.attachment); client.IgnoreNotFound(err) != nil {
			errs = append(errs, fmt.Errorf("delete attachment %s: %w", s.attachment.Name, err))
		}
	}
	if p.lease != nil {
		if err := p.holder.Release(ctx, *p.lease); err != nil {
			errs = append(errs, fmt.Errorf("release lease: %w", err))
		}
	}
	return errors.Join(errs...)
}
