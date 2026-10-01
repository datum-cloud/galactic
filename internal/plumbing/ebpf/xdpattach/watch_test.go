// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// stubSubscriptions replaces both netlink subscriptions with fakes and returns
// a function that pushes one route event, as BGP installing a route does.
func stubSubscriptions(t *testing.T) (pushRoute func()) {
	t.Helper()
	origLink, origRoute, origDebounce, origResync := linkSubscribeFn, routeSubscribeFn, debounceInterval, resyncInterval
	t.Cleanup(func() {
		linkSubscribeFn, routeSubscribeFn, debounceInterval, resyncInterval = origLink, origRoute, origDebounce, origResync
	})
	debounceInterval = time.Millisecond
	resyncInterval = time.Hour

	var routes chan<- netlink.RouteUpdate
	ready := make(chan struct{})
	linkSubscribeFn = func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error {
		return nil
	}
	routeSubscribeFn = func(ch chan<- netlink.RouteUpdate, _ <-chan struct{}, _ netlink.RouteSubscribeOptions) error {
		routes = ch
		close(ready)
		return nil
	}
	return func() {
		<-ready
		routes <- netlink.RouteUpdate{}
	}
}

// runLoop runs OnNetlinkChange with fn until the test ends, and waits for it
// to return before the overrides it reads are restored: cleanups run last in,
// first out, so this must be called after stubSubscriptions.
func runLoop(t *testing.T, fn func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		OnNetlinkChange(ctx, fn)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// TestOnNetlinkChange_ReconcileCoversUplinkResolvedAfterStartup drives issue
// #647's scenario through the loop both datapaths run: the shard starts with
// one uplink resolved, reports the second missing while it cannot attach it,
// and covers it after a route event once it can.
func TestOnNetlinkChange_ReconcileCoversUplinkResolvedAfterStartup(t *testing.T) {
	pushRoute := stubSubscriptions(t)
	h := newSetHost(t, plainLink(testUplink0, 2), plainLink(testUplink1, 3))
	s, startup := newTestSet(t, testUplink0)

	var mu sync.Mutex
	desired := []string{testUplink0}
	results := make(chan []string, 8)

	runLoop(t, func() {
		mu.Lock()
		next := slices.Clone(desired)
		mu.Unlock()
		results <- s.Reconcile(next)
	})
	next := func() []string {
		t.Helper()
		select {
		case missing := <-results:
			return missing
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a re-evaluation")
			return nil
		}
	}

	if missing := next(); len(missing) != 0 {
		t.Fatalf("initial re-evaluation missing = %v, want none", missing)
	}

	// BGP converges over eth1, but its attach fails for now.
	mu.Lock()
	desired = []string{testUplink0, testUplink1}
	h.failFor[testUplink1] = true
	mu.Unlock()
	pushRoute()
	if missing := next(); !slices.Equal(missing, []string{testUplink1}) {
		t.Fatalf("missing = %v, want [eth1]", missing)
	}

	mu.Lock()
	delete(h.failFor, testUplink1)
	mu.Unlock()
	pushRoute()
	if missing := next(); len(missing) != 0 {
		t.Fatalf("missing = %v, want none once eth1 attaches", missing)
	}
	if got := s.Attached(); !slices.Equal(got, []string{testUplink0, testUplink1}) {
		t.Errorf("Attached() = %v, want [eth0 eth1]", got)
	}
	if startup[0].closed {
		t.Error("eth0's startup link was closed")
	}
}

func TestOnNetlinkChange_SubscriptionFailureFallsBackToResync(t *testing.T) {
	stubSubscriptions(t)
	linkSubscribeFn = func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error {
		return errors.New("no netlink")
	}
	routeSubscribeFn = func(chan<- netlink.RouteUpdate, <-chan struct{}, netlink.RouteSubscribeOptions) error {
		return errors.New("no netlink")
	}
	resyncInterval = time.Millisecond

	calls := make(chan struct{}, 8)
	runLoop(t, func() {
		select {
		case calls <- struct{}{}:
		default:
		}
	})

	// The initial evaluation, then at least one driven by the resync alone.
	for range 2 {
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a resync-driven call")
		}
	}
}
