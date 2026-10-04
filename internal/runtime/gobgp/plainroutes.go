// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/srv6"
)

const (
	// plainRouteResync bounds how long a plain route can point the wrong way
	// when no route change was observed, for instance while the route
	// subscription is down.
	plainRouteResync = 30 * time.Second
	// plainRouteDebounce coalesces the burst of route changes an underlay
	// convergence produces into one resync.
	plainRouteDebounce = time.Second
	// plainRouteGCGrace delays removing owned routes no path asks for, so a
	// restarted router does not drop routes it is about to relearn while its
	// sessions come up and the RIB replays.
	plainRouteGCGrace = 2 * time.Minute
)

// Kernel-facing steps of the plain-route reconciler. Package vars so tests can
// drive it without root or a real routing table.
var (
	ensurePlainRouteRules  = srv6.EnsurePlainRouteRules
	plainRouteReplace      = srv6.PlainRouteReplace
	plainRouteDel          = srv6.PlainRouteDel
	plainRouteList         = srv6.PlainRouteList
	removeLegacyPlainRoute = srv6.RemoveLegacyPlainRoute
	watchMainRouteChanges  = subscribeMainRouteChanges
)

// plainRoutes owns this node's plain routes: the kernel routes for EVPN paths
// carrying no route target. See srv6.PlainRouteTable for where they live and
// why the underlay's own routes take precedence over them.
//
// Path events only update the desired set; one goroutine, run, does every
// kernel write. Besides applying path changes, it re-resolves every route's
// next hop whenever the main table changes, and on a timer, since a route
// written while the underlay was still converging otherwise keeps its first
// next hop forever. A route whose next hop cannot be resolved yet is retried
// on the same schedule, not dropped.
//
// It assumes it is the only owner of srv6.PlainRouteTable on this node, which
// holds while one galactic-router runs one BGP runtime per node.
type plainRoutes struct {
	mu sync.Mutex
	// desired maps each prefix to the BGP next hop its best path names.
	desired map[netip.Prefix]net.IP
	// withdrawn holds prefixes withdrawn since the last sync, deleted then
	// even inside the GC grace period.
	withdrawn map[netip.Prefix]struct{}
	// kick wakes run for a desired-set change. Buffered, so a pending wake-up
	// absorbs any further ones.
	kick chan struct{}

	// The fields below are touched only by run's goroutine.

	// failing records prefixes whose last install failed, so a route that
	// cannot be resolved logs once per outage rather than on every resync.
	failing map[netip.Prefix]struct{}
	// migrated records prefixes already checked for a main-table route left
	// by an earlier galactic-router.
	migrated map[netip.Prefix]struct{}
	// rulesReady records that the policy rules are in place.
	rulesReady bool
	// startedAt is when run began, for gcGrace.
	startedAt time.Time

	// report, when non-nil, is given len(failing) after every sync.
	report func(int)

	// resync, debounce and gcGrace default to plainRouteResync,
	// plainRouteDebounce and plainRouteGCGrace; now is time.Now. All are
	// replaceable in tests.
	resync   time.Duration
	debounce time.Duration
	gcGrace  time.Duration
	now      func() time.Time
}

func newPlainRoutes(report func(int)) *plainRoutes {
	return &plainRoutes{
		report:    report,
		desired:   make(map[netip.Prefix]net.IP),
		withdrawn: make(map[netip.Prefix]struct{}),
		kick:      make(chan struct{}, 1),
		failing:   make(map[netip.Prefix]struct{}),
		migrated:  make(map[netip.Prefix]struct{}),
		resync:    plainRouteResync,
		debounce:  plainRouteDebounce,
		gcGrace:   plainRouteGCGrace,
		now:       time.Now,
	}
}

// set records gateway as prefix's next hop and wakes run.
func (p *plainRoutes) set(prefix netip.Prefix, gateway net.IP) {
	p.mu.Lock()
	p.desired[prefix] = gateway
	delete(p.withdrawn, prefix)
	p.mu.Unlock()
	p.wake()
}

// withdraw drops prefix from the desired set and wakes run to delete it.
func (p *plainRoutes) withdraw(prefix netip.Prefix) {
	p.mu.Lock()
	delete(p.desired, prefix)
	p.withdrawn[prefix] = struct{}{}
	p.mu.Unlock()
	p.wake()
}

func (p *plainRoutes) wake() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// run reconciles the kernel until ctx is done. Routes are left in place when
// it returns, so a restarting router keeps forwarding; the next run's garbage
// collection removes any its successor no longer wants.
func (p *plainRoutes) run(ctx context.Context) {
	p.startedAt = p.now()

	resync := time.NewTicker(p.resync)
	defer resync.Stop()
	debounce := time.NewTimer(0)
	<-debounce.C
	defer debounce.Stop()

	changes := p.subscribe(ctx)
	p.sync()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.kick:
			p.sync()
		case _, ok := <-changes:
			if !ok {
				// The subscription died; the resync below restores it.
				changes = nil
				continue
			}
			debounce.Reset(p.debounce)
		case <-debounce.C:
			p.sync()
		case <-resync.C:
			if changes == nil {
				changes = p.subscribe(ctx)
			}
			p.sync()
		}
	}
}

// subscribe starts watching the main table, returning nil if that fails so
// run falls back to its timer until the next attempt.
func (p *plainRoutes) subscribe(ctx context.Context) <-chan struct{} {
	changes, err := watchMainRouteChanges(ctx)
	if err != nil {
		slog.Warn("plainRoutes: cannot watch main-table route changes; re-resolving on a timer only",
			"interval", p.resync, "err", err)
		return nil
	}
	return changes
}

// sync makes the kernel match the desired set, re-resolving every route's
// next hop in the process.
func (p *plainRoutes) sync() {
	if !p.rulesReady {
		if err := ensurePlainRouteRules(); err != nil {
			slog.Error("plainRoutes: install policy rules failed; plain routes are unreachable until they are",
				"err", err)
		} else {
			p.rulesReady = true
		}
	}

	p.mu.Lock()
	desired := make(map[netip.Prefix]net.IP, len(p.desired))
	for prefix, gw := range p.desired {
		desired[prefix] = gw
	}
	withdrawn := p.withdrawn
	p.withdrawn = make(map[netip.Prefix]struct{})
	p.mu.Unlock()

	for prefix := range withdrawn {
		p.migrate(prefix)
		if err := plainRouteDel(prefixToIPNet(prefix)); err != nil {
			slog.Error("plainRoutes: route delete failed", "prefix", prefix, "err", err)
			continue
		}
		delete(p.failing, prefix)
		slog.Info("plainRoutes: route withdrawn", "prefix", prefix)
	}

	for prefix, gw := range desired {
		p.migrate(prefix)
		p.install(prefix, gw)
	}

	if p.now().Sub(p.startedAt) >= p.gcGrace {
		p.collect(desired)
	}

	if p.report != nil {
		p.report(len(p.failing))
	}
}

// install writes one route, logging a change of next hop and the start and
// end of a failure rather than every attempt.
func (p *plainRoutes) install(prefix netip.Prefix, gw net.IP) {
	changed, err := plainRouteReplace(prefixToIPNet(prefix), gw)
	if err != nil {
		if _, already := p.failing[prefix]; !already {
			slog.Warn("plainRoutes: route install failed; retrying as the underlay changes",
				"prefix", prefix, "gw", gw, "err", err)
			p.failing[prefix] = struct{}{}
		}
		return
	}
	if _, wasFailing := p.failing[prefix]; wasFailing {
		delete(p.failing, prefix)
		slog.Info("plainRoutes: route installed after earlier failures", "prefix", prefix, "gw", gw)
		return
	}
	if changed {
		slog.Info("plainRoutes: route installed or next hop updated", "prefix", prefix, "gw", gw)
	}
}

// migrate removes, once per prefix, a main-table route an earlier
// galactic-router installed for it before plain routes had their own table.
func (p *plainRoutes) migrate(prefix netip.Prefix) {
	if _, done := p.migrated[prefix]; done {
		return
	}
	n, err := removeLegacyPlainRoute(prefixToIPNet(prefix))
	if err != nil {
		slog.Warn("plainRoutes: removing legacy main-table route failed", "prefix", prefix, "err", err)
		return
	}
	p.migrated[prefix] = struct{}{}
	if n > 0 {
		slog.Info("plainRoutes: removed legacy main-table route", "prefix", prefix, "count", n)
	}
}

// collect deletes owned routes no desired path accounts for: ones a previous
// run installed for paths withdrawn while no router was running.
func (p *plainRoutes) collect(desired map[netip.Prefix]net.IP) {
	owned, err := plainRouteList()
	if err != nil {
		slog.Warn("plainRoutes: listing owned routes failed", "err", err)
		return
	}
	for _, dst := range owned {
		prefix, ok := ipNetToPrefix(dst)
		if !ok {
			continue
		}
		if _, wanted := desired[prefix]; wanted {
			continue
		}
		if err := plainRouteDel(dst); err != nil {
			slog.Warn("plainRoutes: removing stale route failed", "prefix", prefix, "err", err)
			continue
		}
		slog.Info("plainRoutes: removed route no path asks for", "prefix", prefix)
	}
}

// subscribeMainRouteChanges signals on every main-table route change until ctx
// is done or the subscription fails, then closes the returned channel.
func subscribeMainRouteChanges(ctx context.Context) (<-chan struct{}, error) {
	updates := make(chan netlink.RouteUpdate, 256)
	if err := netlink.RouteSubscribeWithOptions(updates, ctx.Done(), netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) {
			slog.Warn("plainRoutes: route subscription error", "err", err)
		},
	}); err != nil {
		return nil, err
	}
	changes := make(chan struct{}, 1)
	go func() {
		defer close(changes)
		for u := range updates {
			if u.Table != unix.RT_TABLE_MAIN {
				continue
			}
			select {
			case changes <- struct{}{}:
			default:
			}
		}
	}()
	return changes, nil
}

// prefixToIPNet converts prefix to a masked *net.IPNet in its native family's
// length, as addrToIPNet does for path prefixes.
func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return addrToIPNet(prefix.Addr(), prefix.Bits())
}

// ipNetToPrefix is prefixToIPNet's inverse.
func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones).Masked(), true
}
