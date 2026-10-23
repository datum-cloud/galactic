// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
)

// PinnedDatapath is the node's uSID datapath, through its maps pinned under
// PinDir.
type PinnedDatapath struct{ PinDir string }

// Register implements Datapath.
func (d PinnedDatapath) Register(vrfTable, ifindex uint32, ifname string) error {
	return attachreg.RegisterHostLink(d.PinDir, vrfTable, ifindex, ifname)
}

// Unregister implements Datapath.
func (d PinnedDatapath) Unregister(ifindex uint32) error {
	return attachreg.UnregisterHostLink(d.PinDir, ifindex)
}

// pass is the one request every event maps to: each pass reconciles the
// whole node.
var pass = reconcile.Request{NamespacedName: client.ObjectKey{Name: "node"}}

// SetupWithManager runs the agent's passes in mgr: one at start, before any
// attachment event, so links left by an earlier process are found even when
// no attachment remains, then one per attachment change and every Resync.
func (a *Agent) SetupWithManager(mgr ctrl.Manager) error {
	start := make(chan event.GenericEvent, 1)
	start <- event.GenericEvent{Object: &galacticv1alpha1.EdgeAttachment{}}
	toPass := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{pass}
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("edge-agent").
		Watches(&galacticv1alpha1.EdgeAttachment{}, toPass).
		WatchesRawSource(source.Channel(start, toPass)).
		Complete(reconcile.Func(func(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{RequeueAfter: Resync}, a.Reconcile(ctx)
		}))
}
