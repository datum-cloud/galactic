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

// RunSweeper blocks, sweeping the store on a fixed interval until ctx is done.
// It is what actually acts on expired teardown grace periods, and has to be
// polling-driven rather than reactive: VRF teardown is an aggregate condition
// over many routes, not one watched object's transition.
//
// Callers must not start it until the API seed and the store's inventory pass
// have both run.
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
