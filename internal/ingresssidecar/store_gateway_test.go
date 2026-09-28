// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestStoreNoGatewayPublisherIsNoop verifies that a Store with no
// SetGatewayPublisher call — every deployment of this sidecar today —
// behaves exactly as it did before this feature existed: no panic, no
// error, route/VRF reconcile unaffected.
func TestStoreNoGatewayPublisherIsNoop(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}
	if got := backend.vrfCount(); got != 1 {
		t.Errorf("vrfCount = %d, want 1", got)
	}
}

// TestStorePublishesGatewayOnceOnFirstVRFCreation verifies the gateway
// advertisement is published exactly once per VPC's VRF lifetime, not once
// per pod/route reconciled against it.
func TestStorePublishesGatewayOnceOnFirstVRFCreation(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)
	pub := newFakeGatewayPublisher()
	resolver := newFakeGatewayResolver()
	gatewayAddr := net.ParseIP("fd00:99::4")
	resolver.addrs[testVPC1] = gatewayAddr
	store.SetGatewayPublisher(pub, resolver)

	first := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	second := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::2"), SID: net.ParseIP("fd00:99::2")}

	if err := store.SetDesired(ctx, "ns/pod-a", first); err != nil {
		t.Fatalf("SetDesired(pod-a): %v", err)
	}
	if err := store.SetDesired(ctx, "ns/pod-b", second); err != nil {
		t.Fatalf("SetDesired(pod-b): %v", err)
	}

	if got := pub.published[testVPC1]; got == nil || !got.Equal(gatewayAddr) {
		t.Errorf("published[%s] = %v, want %v", testVPC1, got, gatewayAddr)
	}
	if got := len(pub.published); got != 1 {
		t.Errorf("PublishGateway call count (via map size after 2 SetDesired calls for the same VPC) = %d, want 1", got)
	}
}

// TestStoreGatewayNotProvisionedYetIsNotAReconcileError verifies that a
// resolver reporting ErrGatewayAddressNotProvisioned — the common case,
// since no deployment provisions a gateway address yet (see
// GatewayAddressResolver's own doc comment) — never fails the route
// reconcile that triggered it, and leaves the VPC eligible to retry on the
// next SetDesired.
func TestStoreGatewayNotProvisionedYetIsNotAReconcileError(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)
	pub := newFakeGatewayPublisher()
	resolver := newFakeGatewayResolver() // no address seeded for testVPC1

	store.SetGatewayPublisher(pub, resolver)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1 (route reconcile must proceed despite the unresolved gateway)", got)
	}
	if got := len(pub.published); got != 0 {
		t.Errorf("published = %v, want empty (nothing to publish yet)", pub.published)
	}

	// Once an address becomes available, the next SetDesired for this VPC
	// retries and succeeds -- gatewayPublished must not have been latched
	// true on the earlier failed attempt.
	resolver.addrs[testVPC1] = net.ParseIP("fd00:99::4")
	if err := store.SetDesired(ctx, "ns/pod-b", &DesiredRoute{
		VPC: testVPC1, Prefix: mustPrefix(t, "fd00::2"), SID: net.ParseIP("fd00:99::2"),
	}); err != nil {
		t.Fatalf("SetDesired(pod-b): %v", err)
	}
	if got := pub.published[testVPC1]; got == nil {
		t.Error("gateway was never published once an address became available on retry")
	}
}

// TestStorePublishErrorDoesNotFailRouteReconcile verifies a real
// GatewayPublisher error (e.g. a transient k8s API failure) is logged, not
// propagated: a degraded return path must not also block the forward-path
// route this sidecar exists to install.
func TestStorePublishErrorDoesNotFailRouteReconcile(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)
	pub := newFakeGatewayPublisher()
	pub.publishErr = errors.New("simulated transient k8s API failure")
	resolver := newFakeGatewayResolver()
	resolver.addrs[testVPC1] = net.ParseIP("fd00:99::4")
	store.SetGatewayPublisher(pub, resolver)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}
	if got := backend.routeCount(); got != 1 {
		t.Errorf("routeCount = %d, want 1", got)
	}
	if len(pub.published) != 0 {
		t.Errorf("published = %v, want empty (PublishGateway failed)", pub.published)
	}
}

// TestStoreWithdrawsGatewayOnVRFTeardown verifies WithdrawGateway is called
// once a VPC's VRF is actually torn down (its teardown grace period has
// elapsed), not before.
func TestStoreWithdrawsGatewayOnVRFTeardown(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	store := NewStore(backend, testGrace, nil)
	pub := newFakeGatewayPublisher()
	resolver := newFakeGatewayResolver()
	resolver.addrs[testVPC1] = net.ParseIP("fd00:99::4")
	store.SetGatewayPublisher(pub, resolver)

	desired := &DesiredRoute{VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1")}
	if err := store.SetDesired(ctx, "ns/pod-a", desired); err != nil {
		t.Fatalf("SetDesired: %v", err)
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected gateway published before teardown, got %v", pub.published)
	}

	if err := store.SetDesired(ctx, "ns/pod-a", nil); err != nil {
		t.Fatalf("SetDesired(nil): %v", err)
	}

	// Before the route's own grace period elapses: nothing torn down yet.
	start := time.Now()
	store.Sweep(ctx, start)
	if len(pub.withdrawn) != 0 {
		t.Errorf("withdrawn = %v before grace period elapsed, want empty", pub.withdrawn)
	}

	// Once the route's grace period elapses, Sweep removes the route and
	// only then starts the VRF's own grace period (Sweep's own doc
	// comment: the two timers never overlap) -- so the VRF, and this
	// gateway withdrawal, needs one more full grace period after that.
	store.Sweep(ctx, start.Add(testGrace+time.Second))
	if len(pub.withdrawn) != 0 {
		t.Errorf("withdrawn = %v after only the route's grace period, want empty "+
			"(VRF grace hasn't started yet)", pub.withdrawn)
	}

	store.Sweep(ctx, start.Add(2*testGrace+2*time.Second))
	if len(pub.withdrawn) != 1 || pub.withdrawn[0] != testVPC1 {
		t.Errorf("withdrawn = %v, want [%s]", pub.withdrawn, testVPC1)
	}
	if _, ok := pub.published[testVPC1]; ok {
		t.Errorf("published still contains %s after withdrawal", testVPC1)
	}
}
