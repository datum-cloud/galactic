// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package workerroutes hands galactic-router's tenant routes to Galactic
// Worker through the Routes service, whose Fabric module writes them for
// every VPC Worker owns.
//
// A Handoff keeps the routes the router currently installs and its recent
// withdrawals. Each time it opens a stream it sends all of them, because
// Worker keeps routes only in memory, and then sends each change as it
// happens. While Worker is unreachable changes accumulate and are delivered
// once a stream opens again; a route Worker already wrote stays in the
// datapath meanwhile.
//
// Worker acknowledges a withdrawal once it has recorded it, which is before
// its Fabric module removes the entry. A Worker that restarts in between has
// forgotten the withdrawal, so a Handoff keeps an acknowledged withdrawal for
// withdrawalRetention and sends it again on every new stream.
package workerroutes

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

const (
	// maxBatch bounds the routes one request carries.
	maxBatch = 1024
	// retryMin and retryMax bound the wait between connection attempts.
	retryMin = time.Second
	retryMax = 30 * time.Second
	// withdrawalRetention is how long an acknowledged withdrawal is kept and
	// resent on new streams.
	withdrawalRetention = 10 * time.Minute
	// maxWithdrawals bounds the withdrawals kept, above egress_route_table's
	// 32768 entries. Past it the oldest are dropped, acknowledged ones
	// first.
	maxWithdrawals = 65536
)

// Stream is the part of a Routes.Sync stream a Handoff uses.
type Stream interface {
	Send(*workerv1alpha1.RoutesSyncRequest) error
	Recv() (*workerv1alpha1.RoutesSyncResponse, error)
	CloseSend() error
}

// Connect opens a stream to Worker and returns a function closing the
// connection.
type Connect func(ctx context.Context) (Stream, func(), error)

type key struct {
	vpc    string
	prefix netip.Prefix
}

type route struct {
	table uint32
	sid   netip.Addr
}

// withdrawal is one withdrawal the Handoff keeps.
type withdrawal struct {
	// seq is the sequence of the request that last carried it, 0 until one
	// has.
	seq uint64
	// since is when it was withdrawn, and acked when Worker first
	// acknowledged it.
	since, acked time.Time
}

// Handoff hands tenant routes to Worker. Its methods are safe for concurrent
// use.
type Handoff struct {
	connect Connect
	log     *slog.Logger
	now     func() time.Time

	mu        sync.Mutex
	routes    map[key]route
	withdrawn map[key]withdrawal
	// dirty are the keys changed since they were last sent.
	dirty map[key]struct{}
	seq   uint64
	wake  chan struct{}
}

// New returns a Handoff that connects to Worker at socket, presenting the
// token in tokenFile.
func New(socket, tokenFile string) *Handoff {
	return NewWithConnect(func(ctx context.Context) (Stream, func(), error) {
		c, err := workerclient.Dial(ctx, workerclient.Options{
			SocketPath: socket, TokenFile: tokenFile, NoKeepAlive: true,
		})
		if err != nil {
			return nil, nil, err
		}
		s, err := c.SyncRoutes(ctx)
		if err != nil {
			_ = c.Close()
			return nil, nil, err
		}
		return s, func() { _ = c.Close() }, nil
	})
}

// NewWithConnect returns a Handoff that opens streams with connect.
func NewWithConnect(connect Connect) *Handoff {
	return &Handoff{
		connect:   connect,
		log:       slog.Default().With("component", "worker-route-handoff"),
		now:       time.Now,
		routes:    map[key]route{},
		withdrawn: map[key]withdrawal{},
		dirty:     map[key]struct{}{},
		wake:      make(chan struct{}, 1),
	}
}

// Upsert records that the router installs prefix in vpc's table tableID
// toward sid.
func (h *Handoff) Upsert(vpc string, tableID uint32, prefix netip.Prefix, sid net.IP) {
	addr, ok := netip.AddrFromSlice(sid)
	if !ok || vpc == "" {
		return
	}
	k := key{vpc: vpc, prefix: prefix.Masked()}
	h.mu.Lock()
	h.routes[k] = route{table: tableID, sid: addr.Unmap()}
	delete(h.withdrawn, k)
	h.dirty[k] = struct{}{}
	h.mu.Unlock()
	h.signal()
}

// Withdraw records that the router withdrew prefix from vpc.
func (h *Handoff) Withdraw(vpc string, prefix netip.Prefix) {
	if vpc == "" {
		return
	}
	h.mu.Lock()
	h.withdrawLocked(key{vpc: vpc, prefix: prefix.Masked()})
	h.mu.Unlock()
	h.signal()
}

// ForgetTable withdraws every route of vpc it holds in tableID.
func (h *Handoff) ForgetTable(vpc string, tableID uint32) {
	h.mu.Lock()
	for k, r := range h.routes {
		if k.vpc == vpc && r.table == tableID {
			h.withdrawLocked(k)
		}
	}
	h.mu.Unlock()
	h.signal()
}

func (h *Handoff) withdrawLocked(k key) {
	delete(h.routes, k)
	h.withdrawn[k] = withdrawal{since: h.now()}
	h.dirty[k] = struct{}{}
	h.pruneLocked()
}

// pruneLocked drops acknowledged withdrawals older than withdrawalRetention
// and, past maxWithdrawals, the oldest withdrawals, acknowledged ones first.
func (h *Handoff) pruneLocked() {
	now := h.now()
	for k, w := range h.withdrawn {
		if !w.acked.IsZero() && now.Sub(w.acked) > withdrawalRetention {
			delete(h.withdrawn, k)
		}
	}
	if len(h.withdrawn) <= maxWithdrawals {
		return
	}
	keys := make([]key, 0, len(h.withdrawn))
	for k := range h.withdrawn {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := h.withdrawn[keys[i]], h.withdrawn[keys[j]]
		if a.acked.IsZero() != b.acked.IsZero() {
			return !a.acked.IsZero()
		}
		return a.since.Before(b.since)
	})
	drop := len(h.withdrawn) - maxWithdrawals
	h.log.Warn("dropping the oldest tenant route withdrawals kept for galactic-worker", "dropped", drop)
	for _, k := range keys[:drop] {
		delete(h.withdrawn, k)
		delete(h.dirty, k)
	}
}

func (h *Handoff) signal() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// Run keeps a stream to Worker open until ctx is done, reconnecting with
// backoff.
func (h *Handoff) Run(ctx context.Context) {
	wait := retryMin
	connected := false
	for ctx.Err() == nil {
		stream, closeConn, err := h.connect(ctx)
		if err != nil {
			if connected {
				h.log.Info("cannot reach galactic-worker; tenant route changes wait for it", "error", err)
			} else {
				h.log.Debug("cannot reach galactic-worker", "error", err)
			}
			connected = false
		} else {
			if !connected {
				h.log.Info("handing tenant routes to galactic-worker")
			}
			connected = true
			wait = retryMin
			err = h.serve(ctx, stream)
			closeConn()
			if err != nil && ctx.Err() == nil {
				h.log.Info("tenant route stream to galactic-worker ended; reconnecting", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, retryMax)
	}
}

// serve sends every held route and withdrawal on stream, then each change,
// until the stream fails or ctx is done.
func (h *Handoff) serve(ctx context.Context, stream Stream) error {
	h.mu.Lock()
	for k := range h.routes {
		h.dirty[k] = struct{}{}
	}
	for k := range h.withdrawn {
		h.dirty[k] = struct{}{}
	}
	h.mu.Unlock()

	recvErr := make(chan error, 1)
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			h.ack(resp)
		}
	}()
	for {
		if req := h.next(); req != nil {
			if err := stream.Send(req); err != nil {
				return err
			}
			continue
		}
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return nil
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return errors.New("galactic-worker closed the stream")
			}
			return err
		case <-h.wake:
		}
	}
}

// next builds a request from up to maxBatch changed keys, or returns nil.
func (h *Handoff) next() *workerv1alpha1.RoutesSyncRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.dirty) == 0 {
		return nil
	}
	h.seq++
	req := &workerv1alpha1.RoutesSyncRequest{Sequence: h.seq}
	n := 0
	for k := range h.dirty {
		if n == maxBatch {
			break
		}
		n++
		delete(h.dirty, k)
		if r, ok := h.routes[k]; ok {
			req.Upserts = append(req.Upserts, &workerv1alpha1.TenantRoute{
				Vpc: k.vpc, TableId: r.table, Prefix: k.prefix.String(), Sid: r.sid.String(),
			})
			continue
		}
		if w, ok := h.withdrawn[k]; ok {
			w.seq = h.seq
			h.withdrawn[k] = w
			req.Withdrawals = append(req.Withdrawals, &workerv1alpha1.TenantRouteKey{
				Vpc: k.vpc, Prefix: k.prefix.String(),
			})
		}
	}
	return req
}

// ack marks the withdrawals Worker recorded with resp as acknowledged, drops
// expired ones, and logs the routes it rejected.
func (h *Handoff) ack(resp *workerv1alpha1.RoutesSyncResponse) {
	for _, r := range resp.GetRejected() {
		h.log.Warn("galactic-worker rejected a tenant route", "vpc", r.GetKey().GetVpc(),
			"prefix", r.GetKey().GetPrefix(), "reason", r.GetReason(), "message", r.GetMessage())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	for k, w := range h.withdrawn {
		if w.seq != 0 && w.seq <= resp.GetSequence() && w.acked.IsZero() {
			w.acked = now
			h.withdrawn[k] = w
		}
	}
	h.pruneLocked()
}
