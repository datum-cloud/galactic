// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/egressroute"
)

// EgressRouteReconciler runs periodic egress default-route reconciliation
// on this compute node (datum-cloud/enhancements#865, design plan
// §4.4/§7.1) — the ticker-driven wrapper around internal/egressroute.Run,
// mirroring GCReconciler's own split between a thin, time-driven
// controller here and the real logic in a sibling non-controller package
// (internal/gc). Unlike NetworkGatewayReconciler/NetworkEgressPolicyReconciler
// (gateway-node-scoped, registered from cmd/galactic-gateway), this runs
// from cmd/galactic-router's tenant-role process: it needs to see every
// compute node's own local VRF state, not just gateway nodes', and
// galactic-router (tenant role) already runs on every node that could have
// one.
//
// Time-driven, not object-driven, for the same reason GCReconciler is: a
// newly-created local VRF interface is pure kernel state with no
// corresponding Kubernetes watch event to react to, so this can only ever
// notice it on a periodic sweep, not a reactive one.
type EgressRouteReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Namespace string
	NodeName  string
	Interval  time.Duration
}

// slogAdapter adapts log/slog's package-level functions to
// egressroute.Logger, matching GCReconciler's own choice of slog over
// logr.Logger for this package's plain log lines (see gc_controller.go's
// identical use of slog.Info/slog.Error at its own call sites).
type slogAdapter struct{}

func (slogAdapter) Info(msg string, keysAndValues ...any) { slog.Info(msg, keysAndValues...) }
func (slogAdapter) Error(err error, msg string, keysAndValues ...any) {
	slog.Error(msg, append([]any{"err", err}, keysAndValues...)...)
}

// Reconcile runs an egress-route pass at the configured interval. It does
// not watch any Kubernetes resources — it is purely time-driven, same as
// GCReconciler.Reconcile.
func (r *EgressRouteReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	if r.Namespace == "" {
		slog.Debug("EgressRoute: namespace not configured, skipping")
		return ctrl.Result{RequeueAfter: r.Interval}, nil
	}

	result := r.RunOnce(ctx)
	if result.Errors > 0 {
		slog.Info("EgressRoute: completed with errors",
			"routesInstalled", result.RoutesInstalled, "routesRemoved", result.RoutesRemoved, "errors", result.Errors)
	} else if result.RoutesInstalled > 0 || result.RoutesRemoved > 0 {
		slog.Info("EgressRoute: reconcile complete",
			"routesInstalled", result.RoutesInstalled, "routesRemoved", result.RoutesRemoved)
	}

	return ctrl.Result{RequeueAfter: r.Interval}, nil
}

// SetupWithManager registers the EgressRouteReconciler with the manager.
// Like GCReconciler, it is started by a ticker goroutine launched from
// root.go where the manager's context is available.
func (r *EgressRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Interval == 0 {
		r.Interval = 5 * time.Minute
	}
	return nil
}

// RunOnce runs a single egress-route reconcile pass in the given context.
// This is the public API for triggering it from outside the reconciler
// (e.g. root.go's ticker goroutine), mirroring GCReconciler.RunGC.
func (r *EgressRouteReconciler) RunOnce(ctx context.Context) egressroute.Result {
	return egressroute.Run(ctx, r.Client, r.Namespace, r.NodeName, slogAdapter{})
}
