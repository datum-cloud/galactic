// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/route"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
)

// PinnedDatapath is the node's uSID datapath, through its maps pinned under
// PinDir.
type PinnedDatapath struct{ PinDir string }

// Register implements Datapath: the link's gate row first, so the link
// carries only its own address from the moment usid_egress and tp_deliver
// are attached to it, then its traffic policy row and programs
// (attachreg.RegisterHostLink).
func (d PinnedDatapath) Register(vrfTable, ifindex uint32, ifname string, addr netip.Addr) error {
	gates, err := forwardgatemap.OpenPinned(d.PinDir)
	if err != nil {
		return err
	}
	defer func() { _ = gates.Close() }()
	if err := gates.SetLink(ifindex, addr); err != nil {
		return err
	}
	return attachreg.RegisterHostLink(d.PinDir, vrfTable, ifindex, ifname, addr)
}

// Unregister implements Datapath: the link's gates first, then its rows. The
// link row stays until Forget, so the link stays gated while it exists. A
// datapath whose gate maps are not pinned holds no gate.
func (d PinnedDatapath) Unregister(ifindex uint32) error {
	gates, err := forwardgatemap.OpenPinned(d.PinDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		err = gates.DeleteGates(ifindex)
		_ = gates.Close()
		if err != nil {
			return err
		}
	}
	return attachreg.UnregisterHostLink(d.PinDir, ifindex)
}

// Forget implements Datapath.
func (d PinnedDatapath) Forget(ifindex uint32) error {
	gates, err := forwardgatemap.OpenPinned(d.PinDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	}
	defer func() { _ = gates.Close() }()
	return gates.DeleteLink(ifindex)
}

// PinnedGates is the node's forwarding gate, opened from PinDir for every
// call, so a map the datapath's loader recreated is never written through a
// stale handle.
type PinnedGates struct{ PinDir string }

func (g PinnedGates) with(fn func(*forwardgatemap.Table) error) error {
	t, err := forwardgatemap.OpenPinned(g.PinDir)
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()
	return fn(t)
}

// Link implements GateTable.
func (g PinnedGates) Link(ifindex uint32) (addr netip.Addr, ok bool, err error) {
	err = g.with(func(t *forwardgatemap.Table) error {
		addr, ok, err = t.Link(ifindex)
		return err
	})
	return addr, ok, err
}

// Gates implements GateTable.
func (g PinnedGates) Gates(ifindex uint32) (rows map[netip.Prefix]forwardgatemap.Gate, err error) {
	err = g.with(func(t *forwardgatemap.Table) error {
		rows, err = t.Gates(ifindex)
		return err
	})
	return rows, err
}

// Set implements GateTable.
func (g PinnedGates) Set(ifindex uint32, prefix netip.Prefix, gate forwardgatemap.Gate) error {
	return g.with(func(t *forwardgatemap.Table) error { return t.Set(ifindex, prefix, gate) })
}

// Links implements GateTable.
func (g PinnedGates) Links() (links map[uint32]netip.Addr, err error) {
	err = g.with(func(t *forwardgatemap.Table) error {
		links, err = t.Links()
		return err
	})
	return links, err
}

// DeleteLink implements GateTable.
func (g PinnedGates) DeleteLink(ifindex uint32) error {
	return g.with(func(t *forwardgatemap.Table) error { return t.DeleteLink(ifindex) })
}

// Delete implements GateTable.
func (g PinnedGates) Delete(ifindex uint32, prefix netip.Prefix) error {
	return g.with(func(t *forwardgatemap.Table) error { return t.Delete(ifindex, prefix) })
}

// pass is the one request every event maps to: each pass reconciles the
// whole node.
var pass = reconcile.Request{NamespacedName: client.ObjectKey{Name: "node"}}

// SetupWithManager runs the agent in mgr. The attachment pass runs once at
// start, before any attachment event, so links left by an earlier process
// are found even when no attachment remains, then once per attachment change,
// whenever a gate opens or closes, and every Resync. The gate of each route
// accepted on this node is decided on every change to the route, its
// instance (each renewal), attachment or service, and again before it would
// expire; expired gates nobody claims are swept every Resync.
func (a *Agent) SetupWithManager(mgr ctrl.Manager) error {
	start := make(chan event.GenericEvent, 1)
	start <- event.GenericEvent{Object: &galacticv1alpha1.EdgeAttachment{}}
	gated := make(chan event.GenericEvent, 1)
	toPass := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{pass}
	})
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("edge-agent").
		Watches(&galacticv1alpha1.EdgeAttachment{}, toPass).
		WatchesRawSource(source.Channel(start, toPass)).
		WatchesRawSource(source.Channel(gated, toPass)).
		Complete(reconcile.Func(func(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{RequeueAfter: Resync}, a.Reconcile(ctx)
		})); err != nil {
		return err
	}
	if a.Gates == nil {
		return nil
	}

	c := mgr.GetClient()
	routesOf := func(match func(*galacticv1alpha1.EdgeRoute, client.Object) bool) handler.EventHandler {
		return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
			var list galacticv1alpha1.EdgeRouteList
			if err := c.List(ctx, &list); err != nil {
				return nil
			}
			var out []reconcile.Request
			for i := range list.Items {
				rt := &list.Items[i]
				if acc := rt.Status.Accepted; acc != nil && acc.Node == a.NodeName && match(rt, o) {
					out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(rt)})
				}
			}
			return out
		})
	}
	// An instance and its lease share a namespace and name.
	sameInstance := func(rt *galacticv1alpha1.EdgeRoute, o client.Object) bool {
		return rt.Namespace == o.GetNamespace() && rt.Status.Accepted.Instance == o.GetName()
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("edge-gate").
		For(&galacticv1alpha1.EdgeRoute{}).
		Watches(&galacticv1alpha1.EdgeInstance{}, routesOf(sameInstance)).
		// Each renewal of the accepted holder's lease extends its gate.
		Watches(&coordinationv1.Lease{}, routesOf(sameInstance), builder.WithPredicates(route.InstanceLeases)).
		Watches(&galacticv1alpha1.EdgeAttachment{}, routesOf(func(rt *galacticv1alpha1.EdgeRoute, o client.Object) bool {
			return rt.Status.Accepted.AttachmentUID == string(o.GetUID())
		})).
		Watches(&galacticv1alpha1.EdgeService{}, routesOf(func(rt *galacticv1alpha1.EdgeRoute, o client.Object) bool {
			s, ok := o.(*galacticv1alpha1.EdgeService)
			return ok && s.Spec.VPCRef.UID == rt.Spec.VPCUID
		})).
		Watches(&galacticv1alpha1.EdgeProvider{}, routesOf(func(rt *galacticv1alpha1.EdgeRoute, o client.Object) bool {
			return rt.Spec.ProviderRef.Name == o.GetName()
		})).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			changed, after, err := a.GateRoute(ctx, req.NamespacedName)
			if changed {
				select {
				case gated <- event.GenericEvent{Object: &galacticv1alpha1.EdgeAttachment{}}:
				default:
				}
			}
			return reconcile.Result{RequeueAfter: after}, err
		})); err != nil {
		return err
	}
	return mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		t := time.NewTicker(Resync)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
				if err := a.SweepGates(ctx); err != nil {
					ctrl.LoggerFrom(ctx).Error(err, "sweep expired forwarding gates")
				}
			}
		}
	}))
}
