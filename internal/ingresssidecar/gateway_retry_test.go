// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// countingPublisher records every publish and withdrawal, can fail them, and
// can hold a publish until released.
type countingPublisher struct {
	mu        sync.Mutex
	publishes map[string]int
	withdraws map[string]int
	fail      error
	failVPCs  map[string]bool // VPCs whose publish always fails
	hold      chan struct{}   // when set, PublishGateway waits on it or ctx
	started   chan string     // when set, receives each vpc as its publish starts
}

func newCountingPublisher() *countingPublisher {
	return &countingPublisher{publishes: map[string]int{}, withdraws: map[string]int{}}
}

func (p *countingPublisher) PublishGateway(ctx context.Context, vpc string, _ net.IP) error {
	p.mu.Lock()
	hold, started, fail := p.hold, p.started, p.fail
	p.mu.Unlock()
	if started != nil {
		started <- vpc
	}
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if fail != nil {
		return fail
	}
	if p.failVPCs[vpc] {
		return errTest
	}
	p.publishes[vpc]++
	return nil
}

func (p *countingPublisher) WithdrawGateway(_ context.Context, vpc string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail != nil {
		return p.fail
	}
	p.withdraws[vpc]++
	return nil
}

func (p *countingPublisher) set(f func(*countingPublisher)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

func (p *countingPublisher) count(vpc string) (publishes, withdraws int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.publishes[vpc], p.withdraws[vpc]
}

// allResolve resolves every VPC to one address.
type allResolve struct{}

func (allResolve) ResolveGatewayAddress(string) (net.IP, error) {
	return net.ParseIP("fd00:99::4"), nil
}

func retryStore(t *testing.T) (*Store, *fakeBackend, *countingPublisher) {
	t.Helper()
	backend := newFakeBackend()
	store := NewStore(backend, time.Minute, nil)
	pub := newCountingPublisher()
	store.SetGatewayPublisher(pub, allResolve{})
	return store, backend, pub
}

func desireRoute(t *testing.T, s *Store, key, vpc, prefix string) {
	t.Helper()
	if err := s.SetDesired(context.Background(), key, &DesiredRoute{
		VPC: vpc, Prefix: mustPrefix(t, prefix), SID: net.ParseIP("fd00:99::1"),
	}); err != nil {
		t.Fatal(err)
	}
}

// TestFailedPublicationRecoversWithoutAnUpdate: a publish that failed when
// the route was applied succeeds on a later sweep, with no new EndpointSlice
// event, and only once for a VPC with several routes.
func TestFailedPublicationRecoversWithoutAnUpdate(t *testing.T) {
	store, _, pub := retryStore(t)
	pub.set(func(p *countingPublisher) { p.fail = errTest })
	desireRoute(t, store, "ns/a", testVPC1, "fd00::1")
	desireRoute(t, store, "ns/b", testVPC1, "fd00::2")

	store.Sweep(context.Background(), time.Now())
	if n, _ := pub.count(testVPC1); n != 0 {
		t.Fatalf("published %d times while the API fails", n)
	}

	pub.set(func(p *countingPublisher) { p.fail = nil })
	store.Sweep(context.Background(), time.Now())
	if n, _ := pub.count(testVPC1); n != 1 {
		t.Fatalf("published %d times once the API recovered, want 1", n)
	}
	store.Sweep(context.Background(), time.Now())
	if n, _ := pub.count(testVPC1); n != 1 {
		t.Errorf("published %d times; a published VPC must not be republished", n)
	}
}

// TestRetriesAreBoundedAndFair: one sweep retries at most
// gatewayRetriesPerSweep VPCs, and VPCs that keep failing do not stop the
// others from being retried.
func TestRetriesAreBoundedAndFair(t *testing.T) {
	store, _, pub := retryStore(t)
	const vpcs = 10
	name := func(i int) string { return fmt.Sprintf("vpc%02d", i) }
	pub.set(func(p *countingPublisher) {
		p.fail = errTest
		// The first VPCs in retry order never publish.
		p.failVPCs = map[string]bool{}
		for i := range gatewayRetriesPerSweep {
			p.failVPCs[name(i)] = true
		}
	})
	for i := range vpcs {
		desireRoute(t, store, fmt.Sprintf("ns/s%d", i), name(i), fmt.Sprintf("fd00::%x", i+1))
	}
	pub.set(func(p *countingPublisher) { p.fail = nil })

	published := func() int {
		n := 0
		for i := range vpcs {
			if c, _ := pub.count(name(i)); c > 0 {
				n++
			}
		}
		return n
	}
	store.Sweep(context.Background(), time.Now())
	if n := published(); n != 0 {
		t.Fatalf("%d VPCs published by the first sweep, want 0: it retries only the failing ones", n)
	}
	for range 3 {
		store.Sweep(context.Background(), time.Now())
	}
	if n, want := published(), vpcs-gatewayRetriesPerSweep; n != want {
		t.Errorf("%d VPCs published after four sweeps, want %d", n, want)
	}
}

// TestRetryDoesNotHoldTheLock: while a retried publish is waiting on the
// API, route updates still proceed.
func TestRetryDoesNotHoldTheLock(t *testing.T) {
	store, _, pub := retryStore(t)
	pub.set(func(p *countingPublisher) { p.fail = errTest })
	desireRoute(t, store, "ns/a", testVPC1, "fd00::1")
	release, started := make(chan struct{}), make(chan string, 1)
	pub.set(func(p *countingPublisher) { p.fail, p.hold, p.started = nil, release, started })

	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Sweep(context.Background(), time.Now())
	}()
	<-started

	applied := make(chan struct{})
	go func() {
		defer close(applied)
		desireRoute(t, store, "ns/b", testVPC1, "fd00::2") // same VPC: no second publish
	}()
	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("a route update waited on a gateway retry's API call")
	}
	close(release)
	<-done
	if n, _ := pub.count(testVPC1); n != 1 {
		t.Errorf("published %d times, want 1: the update must not publish while a retry is in flight", n)
	}
}

// TestRetryTimesOut: a publish the API never answers is abandoned after
// gatewayRetryTimeout and retried later.
func TestRetryTimesOut(t *testing.T) {
	gatewayRetryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { gatewayRetryTimeout = 10 * time.Second })
	store, _, pub := retryStore(t)
	pub.set(func(p *countingPublisher) { p.fail = errTest })
	desireRoute(t, store, "ns/a", testVPC1, "fd00::1")
	pub.set(func(p *countingPublisher) { p.fail, p.hold = nil, make(chan struct{}) })

	start := time.Now()
	store.Sweep(context.Background(), time.Now())
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the sweep took %v with a hung API", d)
	}
	pub.set(func(p *countingPublisher) { p.hold = nil })
	store.Sweep(context.Background(), time.Now())
	if n, _ := pub.count(testVPC1); n != 1 {
		t.Errorf("published %d times after the API recovered, want 1", n)
	}
}

// TestStalePublicationIsWithdrawn: a publish that completes after its VRF
// was replaced is withdrawn rather than left behind.
func TestStalePublicationIsWithdrawn(t *testing.T) {
	store, _, pub := retryStore(t)
	pub.set(func(p *countingPublisher) { p.fail = errTest })
	desireRoute(t, store, "ns/a", testVPC1, "fd00::1")
	release, started := make(chan struct{}), make(chan string, 1)
	pub.set(func(p *countingPublisher) { p.fail, p.hold, p.started = nil, release, started })

	done := make(chan struct{})
	go func() {
		defer close(done)
		store.retryGateways(context.Background())
	}()
	<-started
	store.mu.Lock()
	delete(store.vrfs, testVPC1) // the VRF is removed while its publish is in flight
	store.mu.Unlock()
	close(release)
	<-done

	if p, w := pub.count(testVPC1); p != 1 || w != 1 {
		t.Errorf("publishes %d, withdrawals %d; want the stale publication withdrawn", p, w)
	}
}

// TestReplacementVRFKeepsThePublication: a publish that completes after its
// VRF was replaced by another for the same VPC counts for the replacement,
// which is neither published twice nor left without its advertisement.
func TestReplacementVRFKeepsThePublication(t *testing.T) {
	store, _, pub := retryStore(t)
	pub.set(func(p *countingPublisher) { p.fail = errTest })
	desireRoute(t, store, "ns/a", testVPC1, "fd00::1")
	release, started := make(chan struct{}), make(chan string, 1)
	pub.set(func(p *countingPublisher) { p.fail, p.hold, p.started = nil, release, started })

	done := make(chan struct{})
	go func() {
		defer close(done)
		store.retryGateways(context.Background())
	}()
	<-started
	store.mu.Lock()
	replacement := &vrfState{installed: true}
	store.vrfs[testVPC1] = replacement
	store.mu.Unlock()
	updated := make(chan struct{})
	go func() {
		defer close(updated)
		desireRoute(t, store, "ns/b", testVPC1, "fd00::2") // in flight: must not publish
	}()
	select {
	case <-updated:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("a route update for an in-flight VPC published again")
	}
	close(release)
	<-done

	if p, w := pub.count(testVPC1); p != 1 || w != 0 {
		t.Errorf("publishes %d, withdrawals %d; want one publication kept", p, w)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !replacement.gatewayPublished {
		t.Error("the replacement VRF does not record the publication it now holds")
	}
	if store.inFlightLocked(testVPC1) {
		t.Error("the VPC is still marked in flight")
	}
}

// TestWithdrawnVRFRepublishesOnReturn: a VRF withdrawn for teardown whose
// removal then fails is published again when its VPC comes back.
func TestWithdrawnVRFRepublishesOnReturn(t *testing.T) {
	store, backend, pub := retryStore(t)
	desireRoute(t, store, "ns/a", testVPC1, "fd00::1")
	if err := store.SetDesired(context.Background(), "ns/a", nil); err != nil {
		t.Fatal(err)
	}
	backend.failRemoveVRF = errTest
	start := time.Now()
	store.Sweep(context.Background(), start.Add(2*time.Minute)) // route removed; VRF grace starts
	store.Sweep(context.Background(), start.Add(5*time.Minute)) // withdrawn, removal fails
	if _, w := pub.count(testVPC1); w != 1 {
		t.Fatalf("withdrawals = %d, want 1", w)
	}

	backend.failRemoveVRF = nil
	desireRoute(t, store, "ns/a", testVPC1, "fd00::1")
	if p, _ := pub.count(testVPC1); p != 2 {
		t.Errorf("publishes = %d, want the returning VPC published again", p)
	}
}

// TestCancelledRetryPublishesNothing: a sweep after shutdown began makes no
// API calls and leaves no VPC marked in flight.
func TestCancelledRetryPublishesNothing(t *testing.T) {
	store, _, pub := retryStore(t)
	pub.set(func(p *countingPublisher) { p.fail = errTest })
	desireRoute(t, store, "ns/a", testVPC1, "fd00::1")
	pub.set(func(p *countingPublisher) { p.fail = nil })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store.retryGateways(ctx)
	if n, _ := pub.count(testVPC1); n != 0 {
		t.Errorf("published %d times after shutdown began", n)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.inFlightLocked(testVPC1) {
		t.Error("the VPC is still marked in flight")
	}
}
