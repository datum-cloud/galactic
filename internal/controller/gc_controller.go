// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/gc"
)

// GCReconciler runs periodic garbage collection to clean up stale BGP CRDs
// and orphaned VRF interfaces left behind when containers are force-terminated
// and CNI DEL never fires.
type GCReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Namespace string
	Interval  time.Duration
}

// Reconcile runs a GC pass at the configured interval. It does not watch any
// Kubernetes resources — it is purely time-driven.
func (r *GCReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	if r.Namespace == "" {
		slog.Debug("GC: namespace not configured, skipping")
		return ctrl.Result{RequeueAfter: r.Interval}, nil
	}

	k8s := r.Client
	result := gc.RunGC(ctx, k8s, r.Namespace)

	if result.Errors > 0 {
		slog.Info("GC: completed with errors",
			"crdsRemoved", result.OrphanedCRDsRemoved,
			"vrfsRemoved", result.OrphanedVRFsRemoved,
			"errors", result.Errors)
	} else if result.OrphanedCRDsRemoved > 0 || result.OrphanedVRFsRemoved > 0 {
		slog.Info("GC: cleanup complete",
			"crdsRemoved", result.OrphanedCRDsRemoved,
			"vrfsRemoved", result.OrphanedVRFsRemoved)
	}

	return ctrl.Result{RequeueAfter: r.Interval}, nil
}

// SetupWithManager registers the GCReconciler with the manager. The GC
// reconciler is started by a ticker goroutine launched from root.go where
// the manager's context is available.
func (r *GCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Interval == 0 {
		r.Interval = 5 * time.Minute
	}
	return nil
}

// RunGC runs a single garbage collection pass in the given context.
// This is the public API for triggering GC from outside the reconciler.
func (r *GCReconciler) RunGC(ctx context.Context) gc.CleanupResult {
	return gc.RunGC(ctx, r.Client, r.Namespace)
}

// GCRequest returns a reconcile.Request that triggers the GC reconciler.
// Used for manual GC triggers (e.g., from metrics or health endpoints).
func GCRequest() ctrl.Request {
	return ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "gc"},
	}
}
