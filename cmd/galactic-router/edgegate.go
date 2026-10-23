// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/edge/timing"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
	"go.datum.net/galactic/internal/reconcile"
)

// edgeGatePoll is how often the router reads the forwarding gates of the
// Galactic Edge prefixes it may advertise. A gate's deadline passes with no
// event, so a prefix is withdrawn within one poll and a reconcile of it.
const edgeGatePoll = 250 * time.Millisecond

// gateTable is the node's pinned forwarding gate
// (internal/plumbing/ebpf/forwardgatemap).
type gateTable interface {
	Open(ifindex uint32, addr netip.Addr, prefix netip.Prefix, now time.Duration) (bool, error)
	Close() error
}

// gateReopen bounds how often a missing or failed gate map is opened again.
const gateReopen = time.Second

// edgeGate checks a Galactic Edge route's advertisement against the node's
// forwarding gate: the host link it names, still the edge link of the
// address it names, holds an unexpired gate for exactly its one prefix. Any
// advertisement it cannot resolve that far is closed.
//
// The gate map is opened on first use and opened again, at most every
// gateReopen, while it is missing or after a read fails, so a router started
// before the uSID datapath picks the gate up without a restart. Until then
// every edge route is closed. A map unpinned and replaced while open is not
// noticed until a read fails: its gates expire and every route it holds
// closes, never the other way.
type edgeGate struct {
	// openTable opens the pinned gate map.
	openTable func() (gateTable, error)
	// clock reads CLOCK_BOOTTIME, the gates' clock.
	clock func() time.Duration
	// now is the wall clock, for reopening.
	now func() time.Time
	// linkIndex resolves a host link's name to its ifindex.
	linkIndex func(name string) (int, error)

	mu       sync.Mutex
	table    gateTable
	lastOpen time.Time
	failed   bool
	closed   bool
}

var _ reconcile.EdgeGate = (*edgeGate)(nil)

// Open implements reconcile.EdgeGate.
func (g *edgeGate) Open(adv *bgpv1alpha1.BGPAdvertisement) bool {
	if len(adv.Spec.Prefixes) != 1 {
		return false
	}
	prefix, err := netip.ParsePrefix(string(adv.Spec.Prefixes[0]))
	if err != nil || prefix != prefix.Masked() {
		return false
	}
	addr, err := netip.ParseAddr(adv.Annotations[crdnames.AnnotationEdgeAddress])
	link := adv.Annotations[crdnames.AnnotationEdgeHostLink]
	if err != nil || link == "" {
		return false
	}
	index, err := g.linkIndex(link)
	if err != nil || index <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	if g.table == nil {
		if now := g.now(); now.Sub(g.lastOpen) >= gateReopen {
			g.lastOpen = now
			t, err := g.openTable()
			if err != nil {
				g.unavailable(err)
				return false
			}
			g.table, g.failed = t, false
			ctrl.Log.Info("forwarding gate opened; Galactic Edge routes are advertised while their gates are open")
		}
		if g.table == nil {
			return false
		}
	}
	open, err := g.table.Open(uint32(index), addr, prefix, g.clock())
	if err != nil {
		// Reopened no sooner than a missing map would be.
		_ = g.table.Close()
		g.table, g.lastOpen = nil, g.now()
		g.unavailable(err)
		return false
	}
	return open
}

// unavailable logs the first failure to read the gate map since it was last
// read.
func (g *edgeGate) unavailable(err error) {
	if !g.failed {
		g.failed = true
		ctrl.Log.Error(err, "forwarding gate not available on this node; "+
			"no Galactic Edge route is advertised until the eBPF uSID datapath is loaded")
	}
}

// Close releases the gate map. Every edge route is closed from then on.
func (g *edgeGate) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	if g.table != nil {
		_ = g.table.Close()
		g.table = nil
	}
}

// setupEdgeGate checks rec's Galactic Edge route advertisements against the
// node's pinned forwarding gate and registers the watch that wakes the
// router when a gate opens or closes. It returns the channel the BGPRouter
// reconciler takes wake-ups from and a function releasing the gate map. A
// route reflector, which never holds the uSID datapath, checks no gate and
// so advertises no edge route; the channel is then nil.
func setupEdgeGate(mgr ctrl.Manager, rec *reconcile.Reconciler, nodeName string, reflector bool,
) (chan event.GenericEvent, func(), error) {
	if reflector {
		return nil, func() {}, nil
	}
	gate := &edgeGate{
		openTable: func() (gateTable, error) {
			t, err := forwardgatemap.OpenPinned(attach.PinDir)
			if err != nil {
				return nil, err
			}
			return t, nil
		},
		clock: timing.BootClock, now: time.Now, linkIndex: netlinkIndex,
	}
	rec.SetEdgeGate(gate)
	wake := make(chan event.GenericEvent, 64)
	if err := mgr.Add(&edgeGateWatch{client: mgr.GetClient(), nodeName: nodeName, gate: gate,
		interval: edgeGatePoll, wake: wake}); err != nil {
		return nil, nil, fmt.Errorf("register edge gate watch: %w", err)
	}
	return wake, gate.Close, nil
}

func netlinkIndex(name string) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, err
	}
	return link.Attrs().Index, nil
}

// edgeGateWatch wakes this node's BGPRouter when the gate of one of its
// Galactic Edge advertisements opened or closed since the last poll, so the
// router rebuilds its desired state and withdraws or advertises the prefix
// with no API event. It reads routers and advertisements from the manager's
// cache and gates from the pinned map: none needs the API server to be
// reachable.
type edgeGateWatch struct {
	client   client.Reader
	nodeName string
	gate     reconcile.EdgeGate
	interval time.Duration
	wake     chan<- event.GenericEvent
}

// NeedLeaderElection implements manager.LeaderElectionRunnable: every node's
// router polls its own gates.
func (w *edgeGateWatch) NeedLeaderElection() bool { return false }

// Start implements manager.Runnable.
func (w *edgeGateWatch) Start(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	last := map[client.ObjectKey]bool{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		var routers bgpv1alpha1.BGPRouterList
		if err := w.client.List(ctx, &routers); err != nil {
			log.FromContext(ctx).Error(err, "list BGPRouters")
			continue
		}
		mine := map[client.ObjectKey]bool{}
		for i := range routers.Items {
			if r := &routers.Items[i]; r.Spec.TargetRef.Name == w.nodeName {
				mine[client.ObjectKeyFromObject(r)] = true
			}
		}
		var list bgpv1alpha1.BGPAdvertisementList
		if err := w.client.List(ctx, &list, client.HasLabels{crdnames.LabelEdgeRoute}); err != nil {
			log.FromContext(ctx).Error(err, "list edge route advertisements")
			continue
		}
		seen := make(map[client.ObjectKey]bool, len(list.Items))
		for i := range list.Items {
			adv := &list.Items[i]
			router := client.ObjectKey{Namespace: adv.Namespace, Name: adv.Spec.RouterRef.Name}
			if !mine[router] {
				continue
			}
			key := client.ObjectKeyFromObject(adv)
			open := w.gate.Open(adv)
			seen[key] = open
			if was, ok := last[key]; ok && was == open {
				continue
			}
			obj := &bgpv1alpha1.BGPRouter{}
			obj.Namespace, obj.Name = router.Namespace, router.Name
			select {
			case w.wake <- event.GenericEvent{Object: obj}:
			case <-ctx.Done():
				return nil
			}
		}
		last = seen
	}
}
