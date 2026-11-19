// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/cache"

	"go.datum.net/galactic/pkg/workerclient"
)

// ClaimsRunner connects the claim manager to Worker and runs it until the
// context ends, then releases the claims. It is a controller-runtime
// Runnable.
type ClaimsRunner struct {
	// Dial opens a Worker session.
	Dial func(ctx context.Context) (*workerclient.Client, error)
	// Build makes the manager over a connected client.
	Build func(client ClaimClient) *Claims
	// Cache is synced before the first pass, so a pass never sees a
	// partial view and releases a claim it still needs.
	Cache    cache.Cache
	Interval time.Duration
	Metrics  *ClaimMetrics
	Log      *slog.Logger

	ready atomic.Pointer[Claims]
}

// releaseTimeout bounds the release of every claim at shutdown.
const releaseTimeout = 5 * time.Second

// Ready is the readiness check: nil once every VPC's claim is held and its
// pod end configured.
func (r *ClaimsRunner) Ready() error {
	c := r.ready.Load()
	if c == nil {
		return errors.New("not connected to Galactic Worker yet")
	}
	return c.Ready()
}

// Start implements manager.Runnable.
func (r *ClaimsRunner) Start(ctx context.Context) error {
	if r.Cache != nil && !r.Cache.WaitForCacheSync(ctx) {
		return ctx.Err()
	}
	backoff := time.Second
	var cl *workerclient.Client
	for cl == nil {
		c, err := r.Dial(ctx)
		if err == nil {
			cl = c
			break
		}
		r.Log.Warn("cannot reach Galactic Worker; retrying", "error", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	defer cl.Close() //nolint:errcheck // closing a finished session
	r.Metrics.SetConnected(true)
	defer r.Metrics.SetConnected(false)
	if caps := cl.Capabilities(); caps != nil {
		r.Metrics.SetCapabilities(caps.GetCapabilities())
	}
	claims := r.Build(cl)
	r.ready.Store(claims)

	kick := make(chan struct{}, 1)
	octx, stopObserve := context.WithCancel(ctx)
	observed := make(chan struct{})
	go func() {
		defer close(observed)
		r.observe(octx, cl, claims, kick)
	}()
	// The stream stops before the client closes, deferred above.
	defer func() {
		stopObserve()
		<-observed
	}()

	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		if err := claims.Sync(ctx); err != nil && ctx.Err() == nil {
			r.Log.Info("Worker claims not converged; retrying", "error", err)
		}
		select {
		case <-ctx.Done():
			rctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
			defer cancel()
			if err := claims.ReleaseAll(rctx); err != nil {
				r.Log.Warn("release Worker claims at shutdown", "error", err)
			} else {
				r.Log.Info("released Worker claims at shutdown")
			}
			return nil
		case <-t.C:
		case <-kick:
		}
	}
}

// observe feeds every status snapshot of the caller's claims to claims,
// reopening the stream with backoff when it ends, and kicks a pass after
// each snapshot.
func (r *ClaimsRunner) observe(ctx context.Context, cl *workerclient.Client, claims *Claims, kick chan struct{}) {
	backoff := time.Second
	for ctx.Err() == nil {
		obs, err := cl.Observe(ctx, nil)
		if err == nil {
			got := false
			for {
				st, err := obs.Recv()
				if err != nil {
					break
				}
				got = true
				claims.Observe(st)
				select {
				case kick <- struct{}{}:
				default:
				}
			}
			if got {
				backoff = time.Second
			}
		} else if ctx.Err() == nil {
			r.Log.Warn("open the Worker status stream", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}
