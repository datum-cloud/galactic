// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"log/slog"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	fabricapi "go.datum.net/galactic/internal/fabric/api/v1alpha1"
)

// Janitor defaults.
const (
	// DefaultRetention is how long a finished query is kept.
	DefaultRetention = time.Hour
	// DefaultCleanupGrace is how long past retention the cell waits for the
	// federation to delete a query before deleting its copy itself.
	DefaultCleanupGrace = 15 * time.Minute
)

// Janitor deletes FabricQuery copies in this cell that the federation failed
// to delete: any query whose expiration or completion, whichever is later,
// is more than Retention plus Grace in the past. It deletes with a UID
// precondition, so a new query reusing a name is never touched, and it never
// creates or modifies anything. Its RBAC is separate from the gateway's.
type Janitor struct {
	Client    client.Client
	Retention time.Duration
	Grace     time.Duration
	Now       func() time.Time
}

// Sweep makes one pass over every namespace and returns the number of
// objects it deleted.
func (j *Janitor) Sweep(ctx context.Context) (int, error) {
	now := time.Now()
	if j.Now != nil {
		now = j.Now()
	}
	retention, grace := j.Retention, j.Grace
	if retention <= 0 {
		retention = DefaultRetention
	}
	if grace <= 0 {
		grace = DefaultCleanupGrace
	}
	deleted := 0
	var cont string
	for {
		var list fabricapi.FabricQueryList
		if err := j.Client.List(ctx, &list, client.Limit(500), client.Continue(cont)); err != nil {
			return deleted, err
		}
		for i := range list.Items {
			fq := &list.Items[i]
			if !stale(fq, now, retention, grace) || fq.DeletionTimestamp != nil {
				continue
			}
			err := j.Client.Delete(ctx, fq, client.Preconditions{UID: &fq.UID})
			outcome := "deleted"
			switch {
			case err == nil:
				deleted++
				slog.Info("deleted expired fabric query", "fabricQuery", client.ObjectKeyFromObject(fq).String(),
					"requestID", fq.Spec.RequestID, "expiredAt", fq.Spec.ExpiresAt.Time)
			case apierrors.IsNotFound(err) || apierrors.IsConflict(err):
				outcome = "gone"
			default:
				outcome = "error"
				slog.Warn("could not delete expired fabric query",
					"fabricQuery", client.ObjectKeyFromObject(fq).String(), "error", err)
			}
			slog.Debug("fabric query sweep outcome", "fabricQuery", client.ObjectKeyFromObject(fq).String(), "outcome", outcome)
		}
		cont = list.Continue
		if cont == "" {
			break
		}
	}
	return deleted, nil
}

// stale reports whether fq is past its expiration or completion, whichever
// is later, by more than retention plus grace.
func stale(fq *fabricapi.FabricQuery, now time.Time, retention, grace time.Duration) bool {
	end := fq.Spec.ExpiresAt.Time
	if c := fq.Status.CompletionTime; c != nil && c.After(end) {
		end = c.Time
	}
	return now.After(end.Add(retention + grace))
}

// StaleCounter publishes how many of this cell's FabricQuery objects are
// stale, from the gateway's cache, so a cleanup backlog is visible even
// though the janitor itself runs as an unscraped CronJob. It runs on every
// replica.
type StaleCounter struct {
	Reader    client.Reader
	Retention time.Duration
	Grace     time.Duration
	Metrics   *Metrics
	Interval  time.Duration
}

// Start counts every Interval until ctx ends.
func (s *StaleCounter) Start(ctx context.Context) error {
	interval := s.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	retention, grace := s.Retention, s.Grace
	if retention <= 0 {
		retention = DefaultRetention
	}
	if grace <= 0 {
		grace = DefaultCleanupGrace
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		var list fabricapi.FabricQueryList
		if err := s.Reader.List(ctx, &list); err == nil {
			n, now := 0, time.Now()
			for i := range list.Items {
				if stale(&list.Items[i], now, retention, grace) {
					n++
				}
			}
			s.Metrics.staleObjects.Set(float64(n))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// NeedLeaderElection is false: every replica reports the same count.
func (*StaleCounter) NeedLeaderElection() bool { return false }

// Run sweeps every interval until ctx ends.
func (j *Janitor) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := j.Sweep(ctx); err != nil {
			slog.Error("fabric query sweep failed", "error", err)
		} else if n > 0 {
			slog.Info("fabric query sweep", "deleted", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
