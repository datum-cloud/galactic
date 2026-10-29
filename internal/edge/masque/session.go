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
	"k8s.io/apimachinery/pkg/types"

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
	attUID     types.UID
	rt         *route
	rtGen      uint64
	leaseKey   string
	leaseEpoch uint64

	done    chan struct{}
	ended   atomic.Bool
	endOnce sync.Once
	// notAfter is the grant's current deadline in Unix nanoseconds on
	// cfg.Now; every packet reads it.
	notAfter atomic.Int64
	// timerMu guards timer, which ends the request at notAfter.
	timerMu sync.Mutex
	timer   *time.Timer
	// pkt is the request's packet path once opened; close closes it.
	pkt atomic.Pointer[packetSession]

	closeOnce sync.Once
	// closed is closed once close has stopped the packet path and dropped
	// the request's references.
	closed chan struct{}
	// drops counts client packets dropped because the device was full.
	drops atomic.Uint64
}

// newSession admits a request of g on e and r, which it takes the caller's
// references to. began is Adapter.revokeSeq when the admission began; a
// Revoke of the connector since refuses it.
func (a *Adapter) newSession(g *Grant, e *attachment, r *route, began uint64) (connectip.Lease, error) {
	l, ok := a.heldLease()
	a.mu.Lock()
	var err error
	switch {
	case !ok || !sameLease(r.lease, l):
		err = errors.New("the lease changed during admission")
	case a.closing:
		err = errors.New("the provider is shutting down")
	case a.revokedAt[g.Connector] > began:
		err = errors.New("the connector was revoked during admission")
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
		a: a, grant: *g, att: e, attGen: r.attGen, attUID: e.uid, rt: r, rtGen: r.gen, leaseKey: l.Key, leaseEpoch: l.Epoch,
		done: make(chan struct{}), closed: make(chan struct{}),
		info: connectip.SessionInfo{
			ID: a.nextID.Add(1), Principal: g.Principal, VPC: g.VPC, Prefix: g.Prefix, Connector: g.Connector,
			Attachment: e.name, Claim: r.name, Epoch: uint64(r.epoch),
		},
	}
	a.sessions[s.info.ID] = s
	s.setDeadline(g.NotAfter)
	go s.refreshLoop()
	a.log.Info("request admitted", "session", s.info.ID, "connector", g.Connector, "principal", g.Principal,
		"serviceUID", g.Service.UID, "attachment", e.name, "attachmentUID", e.uid, "route", r.name, "claimEpoch",
		r.epoch, "instanceEpoch", l.Epoch)
	return s, nil
}

// Info implements connectip.Lease.
func (s *session) Info() connectip.SessionInfo { return s.info }

// Routes implements connectip.Lease.
func (s *session) Routes() []netip.Prefix { return s.grant.Routes }

// Done implements connectip.Lease.
func (s *session) Done() <-chan struct{} { return s.done }

// end stops the request's forwarding and signals Done. The end is counted
// before Done closes, so anyone who sees Done also sees the count. It may be
// called with Adapter.mu held.
func (s *session) end(reason string) {
	s.endOnce.Do(func() {
		s.ended.Store(true)
		label := endReason(reason)
		requestEnds.WithLabelValues(label).Inc()
		close(s.done)
		s.a.log.Info("request ended", "session", s.info.ID, "connector", s.info.Connector, "reason", reason,
			"endReason", label, "serviceUID", s.grant.Service.UID, "attachment", s.info.Attachment,
			"attachmentUID", s.attUID, "route", s.info.Claim, "claimEpoch", s.info.Epoch,
			"instanceEpoch", s.leaseEpoch, "drops", s.drops.Load())
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

// close is Close with the release of the route claim bounded by ctx. It
// closes the request's packet registration before dropping its references,
// so packets the device queued for this request are discarded with it.
func (s *session) close(ctx context.Context) {
	s.closeOnce.Do(func() {
		s.end(reasonClosed)
		s.timerMu.Lock()
		s.timer.Stop()
		s.timerMu.Unlock()
		if p := s.pkt.Swap(closedPacketPath); p != nil {
			_ = p.inner.Close()
		}
		s.a.mu.Lock()
		delete(s.a.sessions, s.info.ID)
		s.a.mu.Unlock()
		s.a.releaseRoute(ctx, s.rt)
		s.a.releaseAttachment(s.att)
		close(s.closed)
	})
}

// setDeadline makes notAfter the request's deadline and ends the request
// when it passes.
func (s *session) setDeadline(notAfter time.Time) {
	s.notAfter.Store(notAfter.UnixNano())
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.ended.Load() {
		return
	}
	s.timer = time.AfterFunc(notAfter.Sub(s.a.cfg.Now()), func() { s.end(reasonGrantExpired) })
}

// refreshTimeout bounds one Refresh call; a slower answer is discarded.
const refreshTimeout = 2 * time.Second

// refreshLoop refreshes the request's grant every cfg.Refresh until the
// request ends. A refused refresh ends only this request. A failed one
// leaves the deadline as it was, so the request ends at it unless a later
// refresh succeeds.
func (s *session) refreshLoop() {
	t := time.NewTicker(s.a.cfg.Refresh)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		if reason := s.refresh(); reason != "" {
			s.end(reason)
			return
		}
	}
}

// refresh makes one Refresh call and applies its result. It returns why the
// request must end, or "".
func (s *session) refresh() string {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()
	go func() {
		select {
		case <-s.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	g, err := s.a.cfg.Authorizer.Refresh(ctx, s.grant)
	switch {
	case errors.Is(err, connectip.ErrUnauthenticated), errors.Is(err, connectip.ErrForbidden):
		return reasonGrantRevoked
	case err != nil:
		s.a.log.Warn("grant refresh failed; the request keeps its deadline", "session", s.info.ID,
			"connector", s.info.Connector, "error", err)
		return ""
	case ctx.Err() != nil:
		// An answer that arrived after its deadline is not fresh authority.
		return ""
	case !s.grant.sameAuthority(&g):
		return reasonGrantChanged
	case g.validate(s.grant.VPC, s.a.cfg.Now()) != nil:
		return reasonGrantInvalid
	}
	s.setDeadline(g.NotAfter)
	return ""
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
		int64(a.cfg.Claims.Clock()) < a.deadline.Load() && a.cfg.Now().UnixNano() < s.notAfter.Load()
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
	p := &packetSession{s: s, inner: inner}
	// A request closed while the device registration was made must not
	// leave it behind.
	if !s.pkt.CompareAndSwap(nil, p) {
		_ = inner.Close()
		return nil, fmt.Errorf("%w: request %d is closed or already open", ErrUnavailable, info.ID)
	}
	return p, nil
}

// closedPacketPath marks a closed request's packet path, so Open cannot
// register one after close.
var closedPacketPath = &packetSession{}

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
		deviceDrops.Inc()
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
