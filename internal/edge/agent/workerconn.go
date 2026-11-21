// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

// WorkerConn is a WorkerClient that connects to Galactic Worker when a call
// needs it and connects again after the connection fails. galactic-edge
// starts, and keeps renewing the gates of links Worker already registered,
// while Worker is down: forwarding never depends on Worker
// (docs/worker/contract.md), and only claiming a link waits for it.
type WorkerConn struct {
	// Dial connects to Worker.
	Dial func(ctx context.Context) (*workerclient.Client, error)

	mu sync.Mutex
	c  *workerclient.Client
}

var _ WorkerClient = (*WorkerConn)(nil)

// errWorkerDown is what a call gets while Worker cannot be reached.
var errWorkerDown = status.Error(codes.Unavailable, "galactic-worker is not reachable")

func (w *WorkerConn) client(ctx context.Context) (*workerclient.Client, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.c != nil {
		return w.c, nil
	}
	c, err := w.Dial(ctx)
	if err != nil {
		return nil, errors.Join(errWorkerDown, err)
	}
	w.c = c
	return c, nil
}

// done drops c after a call failed for want of a connection, so the next call
// connects again with a new session.
func (w *WorkerConn) done(c *workerclient.Client, err error) {
	if status.Code(err) != codes.Unavailable || workerclient.Reason(err) != "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.c == c {
		_ = c.Close()
		w.c = nil
	}
}

// Request implements WorkerClient.
func (w *WorkerConn) Request(ctx context.Context, key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	c, err := w.client(ctx)
	if err != nil {
		return nil, err
	}
	st, err := c.Request(ctx, key, gen, spec)
	w.done(c, err)
	return st, err
}

// Update implements WorkerClient.
func (w *WorkerConn) Update(ctx context.Context, key *workerv1alpha1.ClaimKey, gen uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	c, err := w.client(ctx)
	if err != nil {
		return nil, err
	}
	st, err := c.Update(ctx, key, gen, spec)
	w.done(c, err)
	return st, err
}

// Release implements WorkerClient.
func (w *WorkerConn) Release(ctx context.Context, key *workerv1alpha1.ClaimKey,
	gen uint64) (*workerv1alpha1.ClaimStatus, error) {
	c, err := w.client(ctx)
	if err != nil {
		return nil, err
	}
	st, err := c.Release(ctx, key, gen)
	w.done(c, err)
	return st, err
}

// Observe implements WorkerClient. WorkerDatapath.Run opens a stream that
// ended again; when the connection is gone, that call fails and the next
// one connects again.
func (w *WorkerConn) Observe(ctx context.Context, key *workerv1alpha1.ClaimKey) (*workerclient.Observer, error) {
	c, err := w.client(ctx)
	if err != nil {
		return nil, err
	}
	o, err := c.Observe(ctx, key)
	w.done(c, err)
	return o, err
}

// Capabilities returns Worker's last GetCapabilities response, or nil while
// not connected.
func (w *WorkerConn) Capabilities() *workerv1alpha1.GetCapabilitiesResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.c == nil {
		return nil
	}
	return w.c.Capabilities()
}

// Close closes the connection, if any.
func (w *WorkerConn) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.c == nil {
		return nil
	}
	err := w.c.Close()
	w.c = nil
	return err
}
