// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package masque

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/edge/connectip"
)

// errStopped is returned by a request's packet I/O once it may no longer
// forward.
var errStopped = errors.New("masque: forwarding stopped")

// session is one admitted request: its connectip.Lease and the identities
// its packets are bound to.
type session struct {
	a     *Adapter
	grant Grant
	info  connectip.SessionInfo
	// att and rt are referenced until Close; attGen, rtGen and leaseEpoch
	// are the generations the request was admitted on.
	att        *attachment
	attGen     uint64
	rt         *route
	rtGen      uint64
	leaseKey   string
	leaseEpoch uint64

	done    chan struct{}
	ended   atomic.Bool
	endOnce sync.Once
	timer   *time.Timer

	closeOnce sync.Once
	// drops counts client packets dropped because the device was full.
	drops atomic.Uint64
}

// newSession admits a request of g on e and r, which it takes the caller's
// references to.
func (a *Adapter) newSession(g *Grant, e *attachment, r *route) (connectip.Lease, error) {
	l, ok := a.heldLease()
	a.mu.Lock()
	var err error
	switch {
	case !ok || !sameLease(r.lease, l):
		err = errors.New("the lease changed during admission")
	case a.closing:
		err = errors.New("the provider is shutting down")
	case !r.active || r.att != e || !e.serving(r.attGen):
		err = errors.New("the attachment or route changed during admission")
	}
	if err != nil {
		a.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer cancel()
		a.releaseRoute(ctx, r)
		a.releaseAttachment(e)
		return nil, fmt.Errorf("%w: connector %s: %w", ErrUnavailable, g.Connector, err)
	}
	defer a.mu.Unlock()
	s := &session{
		a: a, grant: *g, att: e, attGen: r.attGen, rt: r, rtGen: r.gen, leaseKey: l.Key, leaseEpoch: l.Epoch,
		done: make(chan struct{}),
		info: connectip.SessionInfo{
			ID: a.nextID.Add(1), Principal: g.Principal, VPC: g.VPC, Prefix: g.Prefix, Connector: g.Connector,
			Attachment: e.name, Claim: r.name, Epoch: uint64(r.epoch),
		},
	}
	a.sessions[s.info.ID] = s
	s.timer = time.AfterFunc(g.NotAfter.Sub(a.cfg.Now()), func() { s.end("grant expired") })
	a.log.Info("request admitted", "session", s.info.ID, "connector", g.Connector, "principal", g.Principal,
		"service", g.Service.UID, "attachment", e.name, "attachmentUID", e.uid, "route", r.name, "claimEpoch",
		r.epoch, "instanceEpoch", l.Epoch)
	return s, nil
}

// Info implements connectip.Lease.
func (s *session) Info() connectip.SessionInfo { return s.info }

// Routes implements connectip.Lease.
func (s *session) Routes() []netip.Prefix { return s.grant.Routes }

// Done implements connectip.Lease.
func (s *session) Done() <-chan struct{} { return s.done }

// end stops the request's forwarding and signals Done. It may be called
// with Adapter.mu held.
func (s *session) end(reason string) {
	s.endOnce.Do(func() {
		s.ended.Store(true)
		close(s.done)
		s.a.log.Info("request ended", "session", s.info.ID, "connector", s.info.Connector, "reason", reason,
			"drops", s.drops.Load())
	})
}

// Close implements connectip.Lease. It releases only this request's
// references: the route claim when it was the connector's last request, and
// the attachment's reference, which leaves the device to other requests.
func (s *session) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
	defer cancel()
	s.close(ctx)
	return nil
}

// close is Close with the release of the route claim bounded by ctx.
func (s *session) close(ctx context.Context) {
	s.closeOnce.Do(func() {
		s.end("closed")
		s.timer.Stop()
		s.a.mu.Lock()
		delete(s.a.sessions, s.info.ID)
		s.a.mu.Unlock()
		s.a.releaseRoute(ctx, s.rt)
		s.a.releaseAttachment(s.att)
	})
}

// forwarding reports whether the request may carry a packet now: it has
// not ended, the instance lease it was admitted under is still held and
// valid, and its grant has not expired.
func (s *session) forwarding() bool {
	if s.ended.Load() {
		return false
	}
	a := s.a
	l := a.lease.Load()
	return l != nil && l.Key == s.leaseKey && l.Epoch == s.leaseEpoch &&
		int64(a.cfg.Claims.Clock()) < a.deadline.Load() && a.cfg.Now().Before(s.grant.NotAfter)
}

// Open implements connectip.PacketBackend. It opens the packet path of an
// admitted request on the device of the attachment it was admitted on.
func (a *Adapter) Open(ctx context.Context, info connectip.SessionInfo) (connectip.BackendSession, error) {
	a.mu.Lock()
	s := a.sessions[info.ID]
	if s == nil || s.info != info {
		a.mu.Unlock()
		return nil, fmt.Errorf("%w: request %d was not admitted", ErrUnavailable, info.ID)
	}
	if !s.att.serving(s.attGen) || !s.rt.active || s.rt.gen != s.rtGen || !s.forwarding() {
		a.mu.Unlock()
		return nil, fmt.Errorf("%w: request %d may no longer forward", ErrUnavailable, info.ID)
	}
	b := s.att.backend
	a.mu.Unlock()
	inner, err := b.Open(ctx, info)
	if err != nil {
		return nil, err
	}
	return &packetSession{s: s, inner: inner}, nil
}

// packetSession is a request's packet path, gated by its session.
type packetSession struct {
	s     *session
	inner connectip.BackendSession
}

// WritePacket forwards a client packet. A full device drops the packet and
// counts it rather than ending the request.
func (p *packetSession) WritePacket(pkt []byte) error {
	if !p.s.forwarding() {
		return errStopped
	}
	err := p.inner.WritePacket(pkt)
	if errors.Is(err, unix.EAGAIN) {
		p.s.drops.Add(1)
		return nil
	}
	return err
}

// ReadPacket returns a packet for the client, or an error once the request
// may no longer forward.
func (p *packetSession) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	n, err := p.inner.ReadPacket(ctx, buf)
	if err == nil && !p.s.forwarding() {
		return 0, errStopped
	}
	return n, err
}

// Close ends this request's packet registration only.
func (p *packetSession) Close() error { return p.inner.Close() }
