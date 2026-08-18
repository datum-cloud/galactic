// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"go.datum.net/galactic/internal/crdnames"
)

// Reconciler is the thin controller-runtime glue that turns EndpointSlice
// watch events into Store.SetDesired calls — all the actual VRF/route
// lifecycle logic lives in Store. Mirrors this repo's other CRD-to-desired-
// state reconcilers (e.g. internal/controller.BGPAdvertisementReconciler)
// in being a pure translation layer with no state of its own.
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
		// Selected but malformed in a way retrying can't fix (a bad
		// annotation isn't going to parse differently on the next attempt)
		// -- log via the returned error (controller-runtime logs Reconcile
		// errors itself) and drop it rather than requeue-looping forever.
		ctrl.LoggerFrom(ctx).Error(err, "skipping malformed EndpointSlice", "endpointslice", req.String())
		return ctrl.Result{}, nil
	}
	if err := r.Store.SetDesired(ctx, req.String(), desired); err != nil {
		return ctrl.Result{}, fmt.Errorf("reconcile EndpointSlice %s: %w", req.NamespacedName, err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller against mgr, watching every
// EndpointSlice cluster-wide — per §3 of the plan, these land in each pod's
// own namespace, not one fixed namespace, so the cache/watch must not be
// namespace-scoped — filtered to only those carrying crdnames.LabelTenantID
// (§3: "select by label presence").
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

// RunSweeper blocks, calling store.Sweep on a fixed interval tick until ctx
// is done — the periodic mechanism that actually acts on expired teardown
// grace periods (see Store.Sweep's own doc comment for why this has to be
// polling-driven rather than reactive: VRF-level teardown is an aggregate
// condition over potentially many routes, not a single watched object's own
// transition). Mirrors cmd/galactic-router's GC ticker goroutine in shape.
//
// Callers must not start this until the manager's informer cache has
// synced and Store.Inventory has run — see Store.Inventory's own doc
// comment.
func RunSweeper(ctx context.Context, store *Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			store.Sweep(ctx, time.Now())
		}
	}
}
