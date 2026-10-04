// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakePlainKernel stands in for the srv6 plain-route helpers. resolve maps a
// gateway to the next hop the "underlay" currently gives it; a gateway absent
// from it does not resolve.
type fakePlainKernel struct {
	mu        sync.Mutex
	resolve   map[string]string
	routes    map[netip.Prefix]string // prefix -> installed next hop
	legacy    map[netip.Prefix]int    // prefix -> main-table routes left by an earlier router
	rulesErr  error
	rulesOK   int
	replaces  int
	legacyChk map[netip.Prefix]int
}

func newFakePlainKernel(t *testing.T) *fakePlainKernel {
	t.Helper()
	k := &fakePlainKernel{
		resolve:   make(map[string]string),
		routes:    make(map[netip.Prefix]string),
		legacy:    make(map[netip.Prefix]int),
		legacyChk: make(map[netip.Prefix]int),
	}

	prevRules, prevReplace, prevDel := ensurePlainRouteRules, plainRouteReplace, plainRouteDel
	prevList, prevLegacy, prevWatch := plainRouteList, removeLegacyPlainRoute, watchMainRouteChanges
	t.Cleanup(func() {
		ensurePlainRouteRules, plainRouteReplace, plainRouteDel = prevRules, prevReplace, prevDel
		plainRouteList, removeLegacyPlainRoute, watchMainRouteChanges = prevList, prevLegacy, prevWatch
	})

	ensurePlainRouteRules = func() error {
		k.mu.Lock()
		defer k.mu.Unlock()
		if k.rulesErr != nil {
			return k.rulesErr
		}
		k.rulesOK++
		return nil
	}
	plainRouteReplace = func(prefix *net.IPNet, gw net.IP) (bool, error) {
		k.mu.Lock()
		defer k.mu.Unlock()
		k.replaces++
		p := mustPrefixFromIPNet(t, prefix)
		nh, ok := k.resolve[gw.String()]
		if !ok {
			return false, errors.New("no route to gateway")
		}
		if k.routes[p] == nh {
			return false, nil
		}
		k.routes[p] = nh
		return true, nil
	}
	plainRouteDel = func(prefix *net.IPNet) error {
		k.mu.Lock()
		defer k.mu.Unlock()
		delete(k.routes, mustPrefixFromIPNet(t, prefix))
		return nil
	}
	plainRouteList = func() ([]*net.IPNet, error) {
		k.mu.Lock()
		defer k.mu.Unlock()
		out := make([]*net.IPNet, 0, len(k.routes))
		for p := range k.routes {
			out = append(out, prefixToIPNet(p))
		}
		return out, nil
	}
	removeLegacyPlainRoute = func(prefix *net.IPNet) (int, error) {
		k.mu.Lock()
		defer k.mu.Unlock()
		p := mustPrefixFromIPNet(t, prefix)
		k.legacyChk[p]++
		n := k.legacy[p]
		delete(k.legacy, p)
		return n, nil
	}
	watchMainRouteChanges = func(context.Context) (<-chan struct{}, error) {
		return nil, errors.New("no subscription in tests")
	}
	return k
}

func (k *fakePlainKernel) nextHop(p netip.Prefix) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nh, ok := k.routes[p]
	return nh, ok
}

func (k *fakePlainKernel) setResolve(gw, nh string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.resolve[gw] = nh
}

func mustPrefixFromIPNet(t *testing.T, n *net.IPNet) netip.Prefix {
	t.Helper()
	p, ok := ipNetToPrefix(n)
	if !ok {
		t.Fatalf("ipNetToPrefix(%v) failed", n)
	}
	return p
}

const (
	nhUnderlay     = "via-underlay"
	nhDefaultRoute = "via-default-route"
)

var (
	shardSIDPrefix = netip.MustParsePrefix("2001:db8:ff02:2002::/64")
	shardGateway   = net.ParseIP("fc00:0:c::1")
)

// newTestPlainRoutes returns a reconciler whose clock starts at start and
// whose GC grace has not yet elapsed.
func newTestPlainRoutes(start time.Time) (*plainRoutes, *time.Time) {
	p := newPlainRoutes(nil)
	clock := start
	p.now = func() time.Time { return clock }
	p.startedAt = start
	return p, &clock
}

// TestPlainRoutes_FollowsUnderlayNextHop is the regression test for #670: a
// route written while the underlay pointed one way must move when it
// converges another way, without any new BGP event.
func TestPlainRoutes_FollowsUnderlayNextHop(t *testing.T) {
	k := newFakePlainKernel(t)
	p, _ := newTestPlainRoutes(time.Now())

	k.setResolve(shardGateway.String(), nhDefaultRoute)
	p.set(shardSIDPrefix, shardGateway)
	p.sync()
	if nh, _ := k.nextHop(shardSIDPrefix); nh != nhDefaultRoute {
		t.Fatalf("next hop = %q, want %q", nh, nhDefaultRoute)
	}

	k.setResolve(shardGateway.String(), nhUnderlay)
	p.sync()
	if nh, _ := k.nextHop(shardSIDPrefix); nh != nhUnderlay {
		t.Errorf("next hop after underlay converged = %q, want %q", nh, nhUnderlay)
	}
}

// TestPlainRoutes_RetriesUnresolvableGateway checks a route whose gateway
// cannot be resolved yet is installed once it can, rather than dropped.
func TestPlainRoutes_RetriesUnresolvableGateway(t *testing.T) {
	k := newFakePlainKernel(t)
	p, _ := newTestPlainRoutes(time.Now())

	p.set(shardSIDPrefix, shardGateway)
	p.sync()
	if _, ok := k.nextHop(shardSIDPrefix); ok {
		t.Fatalf("route installed with no route to its gateway")
	}

	k.setResolve(shardGateway.String(), nhUnderlay)
	p.sync()
	if nh, ok := k.nextHop(shardSIDPrefix); !ok || nh != nhUnderlay {
		t.Errorf("next hop once resolvable = %q (present %v), want %q", nh, ok, nhUnderlay)
	}
}

// TestPlainRoutes_WithdrawDeletesInsideGrace checks a withdrawn path's route is
// deleted at once, even while stray-route GC is still held off.
func TestPlainRoutes_WithdrawDeletesInsideGrace(t *testing.T) {
	k := newFakePlainKernel(t)
	p, _ := newTestPlainRoutes(time.Now())
	k.setResolve(shardGateway.String(), nhUnderlay)

	p.set(shardSIDPrefix, shardGateway)
	p.sync()
	p.withdraw(shardSIDPrefix)
	p.sync()
	if _, ok := k.nextHop(shardSIDPrefix); ok {
		t.Errorf("route still installed after its path was withdrawn")
	}

	// A withdrawal followed by a new best path keeps the route.
	p.withdraw(shardSIDPrefix)
	p.set(shardSIDPrefix, shardGateway)
	p.sync()
	if _, ok := k.nextHop(shardSIDPrefix); !ok {
		t.Errorf("route missing after withdraw then set")
	}
}

// TestPlainRoutes_CollectsStrayRoutesAfterGrace checks an owned route no path
// asks for, left by a previous run, survives the grace period and is removed
// after it, while a desired route is kept.
func TestPlainRoutes_CollectsStrayRoutesAfterGrace(t *testing.T) {
	k := newFakePlainKernel(t)
	start := time.Now()
	p, clock := newTestPlainRoutes(start)
	k.setResolve(shardGateway.String(), nhUnderlay)

	stray := netip.MustParsePrefix("2001:db8:9966:3::1/128")
	k.routes[stray] = "via-old"

	p.set(shardSIDPrefix, shardGateway)
	p.sync()
	if _, ok := k.nextHop(stray); !ok {
		t.Fatalf("stray route removed inside the GC grace period")
	}

	*clock = start.Add(p.gcGrace)
	p.sync()
	if _, ok := k.nextHop(stray); ok {
		t.Errorf("stray route kept after the GC grace period")
	}
	if _, ok := k.nextHop(shardSIDPrefix); !ok {
		t.Errorf("desired route removed by GC")
	}
}

// TestPlainRoutes_MigratesLegacyRouteOnce checks a main-table route left by an
// earlier galactic-router is removed, and that the check runs once per prefix.
func TestPlainRoutes_MigratesLegacyRouteOnce(t *testing.T) {
	k := newFakePlainKernel(t)
	p, _ := newTestPlainRoutes(time.Now())
	k.setResolve(shardGateway.String(), nhUnderlay)
	k.legacy[shardSIDPrefix] = 1

	p.set(shardSIDPrefix, shardGateway)
	p.sync()
	p.sync()

	if k.legacy[shardSIDPrefix] != 0 {
		t.Errorf("legacy route not removed")
	}
	if got := k.legacyChk[shardSIDPrefix]; got != 1 {
		t.Errorf("legacy check ran %d times, want 1", got)
	}
}

// TestPlainRoutes_RetriesPolicyRules checks a failure to install the policy
// rules is retried on the next sync, and that they are not reinstalled once in
// place.
func TestPlainRoutes_RetriesPolicyRules(t *testing.T) {
	k := newFakePlainKernel(t)
	p, _ := newTestPlainRoutes(time.Now())

	k.rulesErr = errors.New("EPERM")
	p.sync()
	if p.rulesReady {
		t.Fatalf("rulesReady = true after a failed install")
	}
	k.rulesErr = nil
	p.sync()
	p.sync()
	if !p.rulesReady || k.rulesOK != 1 {
		t.Errorf("rulesReady = %v, successful installs = %d, want true and 1", p.rulesReady, k.rulesOK)
	}
}

// TestPlainRoutes_RunResyncsOnRouteChange drives run itself: a main-table
// change must re-resolve routes without waiting for the periodic resync.
func TestPlainRoutes_RunResyncsOnRouteChange(t *testing.T) {
	k := newFakePlainKernel(t)
	changes := make(chan struct{}, 1)
	watchMainRouteChanges = func(context.Context) (<-chan struct{}, error) { return changes, nil }

	p := newPlainRoutes(nil)
	p.resync = time.Hour
	p.debounce = time.Millisecond
	k.setResolve(shardGateway.String(), nhDefaultRoute)
	p.set(shardSIDPrefix, shardGateway)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitFor(t, func() bool {
		nh, _ := k.nextHop(shardSIDPrefix)
		return nh == nhDefaultRoute
	})

	k.setResolve(shardGateway.String(), nhUnderlay)
	changes <- struct{}{}
	waitFor(t, func() bool {
		nh, _ := k.nextHop(shardSIDPrefix)
		return nh == nhUnderlay
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPlainRoutes_ReportsFailingRoutes checks the reported count follows the
// routes whose install is failing.
func TestPlainRoutes_ReportsFailingRoutes(t *testing.T) {
	k := newFakePlainKernel(t)
	p, _ := newTestPlainRoutes(time.Now())
	failing := -1
	p.report = func(n int) { failing = n }

	p.set(shardSIDPrefix, shardGateway)
	p.sync()
	if failing != 1 {
		t.Fatalf("failing = %d with an unresolvable gateway, want 1", failing)
	}

	k.setResolve(shardGateway.String(), nhUnderlay)
	p.sync()
	if failing != 0 {
		t.Errorf("failing = %d once the gateway resolves, want 0", failing)
	}
}
