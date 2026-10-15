// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"go.datum.net/galactic/internal/crdnames"
)

// Reconciler is the controller-runtime glue turning EndpointSlice watch events
// into desired-state updates on the Store, where all the actual VRF and route
// lifecycle logic lives. A pure translation layer with no state of its own.
type Reconciler struct {
	client.Client
	Store *Store
}

// Reconcile implements reconcile.Reconciler.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	slice := &discoveryv1.EndpointSlice{}
	err := r.Get(ctx, req.NamespacedName, slice)
	switch {
	case apierrors.IsNotFound(err):
		if serr := r.Store.SetDesired(ctx, req.String(), nil); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mark EndpointSlice %s absent: %w", req.NamespacedName, serr)
		}
		return ctrl.Result{}, nil
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get EndpointSlice %s: %w", req.NamespacedName, err)
	}

	desired, err := BuildDesiredRoute(slice)
	if err != nil {
		// Selected but malformed in a way retrying cannot fix: a bad annotation
		// will not parse differently next time. Log through the returned
		// error, which controller-runtime logs itself, and drop it rather than
		// requeue-loop forever.
		ctrl.LoggerFrom(ctx).Error(err, "skipping malformed EndpointSlice", "endpointslice", req.String())
		return ctrl.Result{}, nil
	}
	if err := r.Store.SetDesired(ctx, req.String(), desired); err != nil {
		return ctrl.Result{}, fmt.Errorf("reconcile EndpointSlice %s: %w", req.NamespacedName, err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller against mgr, watching every
// EndpointSlice cluster-wide, since these land in each pod's own namespace
// rather than one fixed namespace, and filtering to those carrying the tenant
// label.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()
	return ctrl.NewControllerManagedBy(mgr).
		For(&discoveryv1.EndpointSlice{}, builder.WithPredicates(predicate.NewPredicateFuncs(hasTenantLabel))).
		Complete(r)
}

func hasTenantLabel(obj client.Object) bool {
	_, ok := obj.GetLabels()[crdnames.LabelTenantID]
	return ok
}

// seedRetryInitial and seedRetryMax bound the backoff between failed attempts
// to list EndpointSlices at startup. Variables so tests can shorten them.
var (
	seedRetryInitial = time.Second
	seedRetryMax     = 30 * time.Second
)

// RunStartup blocks, seeding store from reader, taking its inventory of host
// state, removing the eBPF map rows an earlier sidecar pod left behind, then
// sweeping it every interval until ctx is done.
//
// The prune runs only after a successful inventory. A failed one can leave a
// VRF in this pod untracked, and pruning then would remove its live rows.
//
// Only a failed EndpointSlice list holds the sweep back, retried with backoff:
// running Inventory without the seed would reopen the race SeedFromAPI closes.
// A slice that fails to apply does not, since the store still records it as
// desired and the sweep both retries it and keeps cleaning up everything else.
//
// metrics, which may be nil, reports each stage's progress and the sweep's.
func RunStartup(ctx context.Context, reader client.Reader, store *Store, interval time.Duration,
	metrics *LifecycleMetrics,
) {
	delay := seedRetryInitial
	for {
		metrics.setStage(StageSeed, StatusRunning)
		err := SeedFromAPI(ctx, reader, store)
		if ctx.Err() != nil {
			return // shutting down: an interrupted attempt is not a result
		}
		metrics.attempt(StageSeed, err)
		if err == nil {
			break
		}
		slog.Error("ingresssidecar: startup seed; retrying", "retryIn", delay, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, seedRetryMax)
	}

	metrics.setStage(StageInventory, StatusRunning)
	err := store.Inventory(ctx, time.Now())
	if ctx.Err() != nil {
		return
	}
	metrics.attempt(StageInventory, err)
	if err != nil {
		slog.Error("ingresssidecar: startup inventory", "error", err)
		metrics.setStage(StagePrune, StatusSkipped)
	} else {
		metrics.setStage(StagePrune, StatusRunning)
		removed, err := store.PruneForeignDatapath()
		metrics.pruned(removed)
		if ctx.Err() != nil {
			return
		}
		metrics.attempt(StagePrune, err)
		if err != nil {
			// Not retried: the rows it leaves only hold map slots until the
			// next sidecar pod's startup prune, or until the host's installer
			// judges every sidecar on this node gone.
			slog.Error("ingresssidecar: startup prune", "error", err)
		}
	}
	metrics.startupComplete()
	RunSweeper(ctx, store, interval, metrics)
}

// RunSweeper blocks, sweeping the store on a fixed interval until ctx is done.
// It is what actually acts on expired teardown grace periods, and has to be
// polling-driven rather than reactive: VRF teardown is an aggregate condition
// over many routes, not one watched object's transition.
//
// Callers must not start it until the API seed and the store's inventory pass
// have both run. metrics, which may be nil, records each completed sweep.
func RunSweeper(ctx context.Context, store *Store, interval time.Duration, metrics *LifecycleMetrics) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := metrics.sweepStart()
			store.Sweep(ctx, time.Now())
			metrics.sweepDone(start)
		}
	}
}
