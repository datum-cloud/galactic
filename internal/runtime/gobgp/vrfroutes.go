// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

const (
	// vrfRouteRetry bounds how long a failed VRF route waits for another
	// attempt when no main-table change was observed.
	vrfRouteRetry = 30 * time.Second
	// vrfRouteDebounce coalesces the burst of route changes an underlay
	// convergence produces into one retry pass.
	vrfRouteDebounce = time.Second
)

// Kernel-facing steps of the VRF route installer. Package vars so tests can
// drive it without root or a pinned egress_route_table.
var (
	vrfRouteAdd = srv6.RouteEgressAdd
	vrfRouteDel = srv6.RouteEgressDel
)

// labelRouter is the log attribute and metric label naming a BGPRouter by its
// namespace/name.
const labelRouter = "router"

// routeInstallFailing counts, per BGPRouter and kind of route, the routes whose
// best path is known but whose last install failed. kind is "vrf" for tenant
// routes in a VRF's egress_route_table and "plain" for routes with no route
// target. A value that stays above zero means part of a VPC, or an egress shard
// or VIP, is unreachable from this node.
var routeInstallFailing = metrics.NewGaugeVec(prometheus.GaugeOpts{
	Name: "galactic_router_route_install_failing",
	Help: "Routes whose best path is known but whose last install into the kernel or datapath failed.",
}, []string{labelRouter, "kind"})

// installFailingReporter returns a report func setting router's
// routeInstallFailing gauge for kind.
func installFailingReporter(router, kind string) func(int) {
	gauge := routeInstallFailing.WithLabelValues(router, kind)
	gauge.Set(0)
	return func(n int) { gauge.Set(float64(n)) }
}

// TenantRouteSink receives every tenant route the router installs or
// withdraws, by VPC. galactic-worker's route handoff implements it.
type TenantRouteSink interface {
	Upsert(vpc string, tableID uint32, prefix netip.Prefix, sid net.IP)
	Withdraw(vpc string, prefix netip.Prefix)
	// ForgetTable withdraws every route of vpc it holds in tableID, for a VRF
	// removed or moved to another table.
	ForgetTable(vpc string, tableID uint32)
}

// VPCFence runs mutate under vpc's write fence. It returns an error wrapping
// ownership.ErrWorkerOwned, and runs nothing, when a galactic-worker
// incarnation owns vpc's scope; Worker then writes the VPC's tenant routes
// from what the sink handed it.
type VPCFence func(vpc string, mutate func() error) error

// OwnershipFence returns the VPCFence of auth, the node's VPC write fence.
func OwnershipFence(auth *ownership.Authority) VPCFence {
	return func(vpc string, mutate func() error) error {
		return auth.ExclusiveIf(ownership.VPCScope(vpc), ownership.RefuseWorkerOwned, mutate)
	}
}

// vrfRouteKey names one tenant route: its prefix in one VRF's table.
type vrfRouteKey struct {
	tableID uint32
	prefix  netip.Prefix
}

// vrfRoutes installs this node's tenant VRF routes into egress_route_table and
// retries any whose install failed.
//
// An install fails while the SID's uplink or its neighbor is not yet usable,
// typically while the underlay converges after a restart. BGP never redelivers
// an unchanged best path, so a failed route is kept in pending and retried
// whenever the main table changes, and on a timer, until it installs or its
// path is withdrawn.
//
// mu serializes every write this runtime makes to egress_route_table, so a
// retry can never reinstall a route the watcher has withdrawn meanwhile.
// A retry takes it per route rather than for the whole pass, since an
// unresolvable neighbor costs up to two seconds each and the watcher must not
// wait for all of them.
type vrfRoutes struct {
	mu sync.Mutex
	// pending maps each route whose last install failed to its gateway.
	pending map[vrfRouteKey]net.IP
	// pendingDel holds each route whose last removal failed.
	pendingDel map[vrfRouteKey]struct{}

	// vpcOf names the VPC whose VRF uses a table, or "" when it is unknown.
	// sink, when set, is handed every route installed or withdrawn. fence,
	// when set, guards every write; a write it refuses because Worker owns
	// the VPC is Worker's to make. Each is nil when the router runs without
	// Worker or the fence.
	vpcOf func(tableID uint32) string
	sink  TenantRouteSink
	fence VPCFence

	// report, when non-nil, is given len(pending) after every change.
	report func(int)

	// retry and debounce default to vrfRouteRetry and vrfRouteDebounce, and
	// are replaceable in tests.
	retry    time.Duration
	debounce time.Duration
}

func newVRFRoutes(report func(int)) *vrfRoutes {
	return &vrfRoutes{
		pending:    make(map[vrfRouteKey]net.IP),
		pendingDel: make(map[vrfRouteKey]struct{}),
		report:     report,
		retry:      vrfRouteRetry,
		debounce:   vrfRouteDebounce,
	}
}

// install writes key's route toward gw, recording it for retry on failure.
func (v *vrfRoutes) install(key vrfRouteKey, gw net.IP) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.installLocked(key, gw)
}

// withdraw stops retrying key and removes its route. A removal that fails is
// retried with the pending installs.
func (v *vrfRoutes) withdraw(key vrfRouteKey) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.pending[key]; ok {
		delete(v.pending, key)
		v.reportLocked()
	}
	vpc := v.vpc(key.tableID)
	if v.sink != nil && vpc != "" {
		v.sink.Withdraw(vpc, key.prefix)
	}
	err := v.write(vpc, func() error { return vrfRouteDel(prefixToIPNet(key.prefix), key.tableID) })
	if err != nil {
		v.pendingDel[key] = struct{}{}
		return err
	}
	delete(v.pendingDel, key)
	return nil
}

// vpc returns the VPC of tableID, or "".
func (v *vrfRoutes) vpc(tableID uint32) string {
	if v.vpcOf == nil {
		return ""
	}
	return v.vpcOf(tableID)
}

// write runs mutate under vpc's fence. A write the fence refuses because
// Worker owns the VPC succeeds without running, since Worker writes it from
// what the sink was handed.
func (v *vrfRoutes) write(vpc string, mutate func() error) error {
	if v.fence == nil || vpc == "" {
		return mutate()
	}
	err := v.fence(vpc, mutate)
	if errors.Is(err, ownership.ErrWorkerOwned) {
		slog.Debug("vrfRoutes: galactic-worker owns the VPC; leaving the route to it", "vpc", vpc)
		return nil
	}
	return err
}

// forgetTable stops retrying every route in tableID, for a VRF of vpc being
// removed or moved, and withdraws the routes handed to the sink for it.
func (v *vrfRoutes) forgetTable(vpc string, tableID uint32) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sink != nil && vpc != "" {
		v.sink.ForgetTable(vpc, tableID)
	}
	changed := false
	for key := range v.pending {
		if key.tableID == tableID {
			delete(v.pending, key)
			changed = true
		}
	}
	for key := range v.pendingDel {
		if key.tableID == tableID {
			delete(v.pendingDel, key)
		}
	}
	if changed {
		v.reportLocked()
	}
}

// installLocked logs the start and end of a failure rather than every attempt.
func (v *vrfRoutes) installLocked(key vrfRouteKey, gw net.IP) {
	_, wasFailing := v.pending[key]
	delete(v.pendingDel, key)
	vpc := v.vpc(key.tableID)
	if v.sink != nil && vpc != "" {
		v.sink.Upsert(vpc, key.tableID, key.prefix, gw)
	}
	if err := v.write(vpc, func() error {
		return vrfRouteAdd(prefixToIPNet(key.prefix), gw, key.tableID)
	}); err != nil {
		if !wasFailing {
			slog.Warn("vrfRoutes: route install failed; retrying as the underlay changes",
				"prefix", key.prefix, "gw", gw, "table", key.tableID, "err", err)
		}
		v.pending[key] = gw
		if !wasFailing {
			v.reportLocked()
		}
		return
	}
	if wasFailing {
		delete(v.pending, key)
		v.reportLocked()
		slog.Info("vrfRoutes: route installed after earlier failures",
			"prefix", key.prefix, "gw", gw, "table", key.tableID)
	}
}

func (v *vrfRoutes) reportLocked() {
	if v.report != nil {
		v.report(len(v.pending))
	}
}

// retryPending makes one attempt at every pending route. A route withdrawn,
// installed or given a new gateway since the snapshot was taken is left to
// whoever changed it.
func (v *vrfRoutes) retryPending() {
	v.mu.Lock()
	snapshot := maps.Clone(v.pending)
	v.mu.Unlock()

	for key, gw := range snapshot {
		v.mu.Lock()
		if current, ok := v.pending[key]; ok && current.Equal(gw) {
			v.installLocked(key, gw)
		}
		v.mu.Unlock()
	}

	v.mu.Lock()
	deletes := maps.Clone(v.pendingDel)
	v.mu.Unlock()
	for key := range deletes {
		v.mu.Lock()
		if _, ok := v.pendingDel[key]; ok {
			if err := v.write(v.vpc(key.tableID), func() error {
				return vrfRouteDel(prefixToIPNet(key.prefix), key.tableID)
			}); err == nil {
				delete(v.pendingDel, key)
			}
		}
		v.mu.Unlock()
	}
}

// run retries pending routes until ctx is done.
func (v *vrfRoutes) run(ctx context.Context) {
	ticker := time.NewTicker(v.retry)
	defer ticker.Stop()
	debounce := time.NewTimer(0)
	<-debounce.C
	defer debounce.Stop()

	changes := v.subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-changes:
			if !ok {
				// The subscription died; the next tick restores it.
				changes = nil
				continue
			}
			debounce.Reset(v.debounce)
		case <-debounce.C:
			v.retryPending()
		case <-ticker.C:
			if changes == nil {
				changes = v.subscribe(ctx)
			}
			v.retryPending()
		}
	}
}

// subscribe starts watching the main table, returning nil if that fails so
// run falls back to its timer until the next attempt.
func (v *vrfRoutes) subscribe(ctx context.Context) <-chan struct{} {
	changes, err := watchMainRouteChanges(ctx)
	if err != nil {
		slog.Warn("vrfRoutes: cannot watch main-table route changes; retrying failed routes on a timer only",
			"interval", v.retry, "err", err)
		return nil
	}
	return changes
}
