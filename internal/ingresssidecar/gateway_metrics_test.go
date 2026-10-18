// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

const (
	mGatewayVRFs      = "galactic_ingress_sidecar_gateway_vrfs"
	mGatewayOldest    = "galactic_ingress_sidecar_gateway_oldest_pending_timestamp_seconds"
	mGatewayOps       = "galactic_ingress_sidecar_gateway_operations_total"
	mGatewayPubOn     = "galactic_ingress_sidecar_gateway_publication_enabled"
	mGatewayAssignOn  = "galactic_ingress_sidecar_gateway_address_assignment_enabled"
	gatewayClockStart = 1_700_000_000
)

type gatewayStore struct {
	*Store
	backend  *fakeBackend
	pub      *fakeGatewayPublisher
	resolver *fakeGatewayResolver
	reg      *prometheus.Registry
	mu       sync.Mutex
	now      time.Time
}

// newGatewayStore is a Store with gateway publication on (publisher and
// resolver set) unless disabled, reporting to its own registry.
func newGatewayStore(t *testing.T, enabled bool) *gatewayStore {
	t.Helper()
	g := &gatewayStore{
		backend:  newFakeBackend(),
		pub:      newFakeGatewayPublisher(),
		resolver: newFakeGatewayResolver(),
		reg:      prometheus.NewPedanticRegistry(),
		now:      time.Unix(gatewayClockStart, 0),
	}
	m := NewGatewayMetrics(enabled, enabled)
	m.now = func() time.Time {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.now
	}
	m.MustRegister(g.reg)
	g.Store = NewStore(g.backend, time.Minute, nil)
	if enabled {
		g.SetGatewayPublisher(g.pub, g.resolver)
	}
	g.SetGatewayMetrics(m)
	return g
}

func (g *gatewayStore) step(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.now = g.now.Add(d)
}

func (g *gatewayStore) value(t *testing.T, name string, labels ...string) float64 {
	t.Helper()
	families, err := g.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	series:
		for _, m := range f.GetMetric() {
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			for i := 0; i+1 < len(labels); i += 2 {
				if got[labels[i]] != labels[i+1] {
					continue series
				}
			}
			return m.GetGauge().GetValue() + m.GetCounter().GetValue()
		}
	}
	return -1
}

// vrfs asserts each gateway state's VRF count and the oldest wait, at
// seconds after the clock started (or 0 for none).
func (g *gatewayStore) vrfs(t *testing.T, awaitingAddress, awaitingPublication, published, oldestAfter float64) {
	t.Helper()
	for state, want := range map[string]float64{
		GatewayAwaitingAddress: awaitingAddress, GatewayAwaitingPublication: awaitingPublication,
		GatewayPublished: published,
	} {
		if v := g.value(t, mGatewayVRFs, "state", state); v != want {
			t.Errorf("gateway_vrfs{state=%q} = %v, want %v", state, v, want)
		}
	}
	want := 0.0
	if oldestAfter >= 0 {
		want = gatewayClockStart + oldestAfter
	}
	if v := g.value(t, mGatewayOldest); v != want {
		t.Errorf("gateway_oldest_pending_timestamp_seconds = %v, want %v", v, want)
	}
}

func (g *gatewayStore) ops(t *testing.T, op, result string, want float64) {
	t.Helper()
	if v := g.value(t, mGatewayOps, "operation", op, "result", result); v != want {
		t.Errorf("gateway_operations_total{operation=%q,result=%q} = %v, want %v", op, result, v, want)
	}
}

func (g *gatewayStore) desire(t *testing.T, key, vpc, prefix string) {
	t.Helper()
	if err := g.SetDesired(context.Background(), key, &DesiredRoute{
		VPC: vpc, Prefix: mustPrefix(t, prefix), SID: net.ParseIP("fd00:99::1"),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayMetricsInitialState(t *testing.T) {
	g := newGatewayStore(t, true)
	families, err := g.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]dto.MetricType{
		mGatewayVRFs: dto.MetricType_GAUGE, mGatewayOldest: dto.MetricType_GAUGE, mGatewayOps: dto.MetricType_COUNTER,
		mGatewayPubOn: dto.MetricType_GAUGE, mGatewayAssignOn: dto.MetricType_GAUGE,
	}
	if len(families) != len(types) {
		t.Errorf("exported %d families, want %d", len(families), len(types))
	}
	for _, f := range families {
		if f.GetType() != types[f.GetName()] || strings.TrimSpace(f.GetHelp()) == "" {
			t.Errorf("%s: type %v, help %q", f.GetName(), f.GetType(), f.GetHelp())
		}
	}
	g.vrfs(t, 0, 0, 0, -1)
	series := len(gatewayStates) + 3 // states, oldest, two enabled gauges
	for _, results := range gatewayOps {
		series += len(results)
	}
	if n := testutil.CollectAndCount(g.reg); n != series {
		t.Errorf("%d series, want %d", n, series)
	}
}

// TestGatewayDisabledCountsNothing: with publication off, VRFs are not
// counted as waiting, and the enabled gauges say so.
func TestGatewayDisabledCountsNothing(t *testing.T) {
	g := newGatewayStore(t, false)
	g.desire(t, "ns/a", testVPC1, "fd00::1")
	g.vrfs(t, 0, 0, 0, -1)
	for op, results := range gatewayOps {
		for _, result := range results {
			g.ops(t, op, result, 0)
		}
	}
	if g.value(t, mGatewayPubOn) != 0 || g.value(t, mGatewayAssignOn) != 0 {
		t.Error("a disabled sidecar reports gateway publication enabled")
	}
}

// TestGatewayStates: a VRF waits for an address, then for publication, then
// is published, its wait starting the first time it is counted as waiting
// and surviving retries; resolve and publish outcomes are counted.
func TestGatewayStates(t *testing.T) {
	g := newGatewayStore(t, true)
	g.desire(t, "ns/a", testVPC1, "fd00::1")
	g.vrfs(t, 1, 0, 0, 0)
	g.ops(t, GatewayOpResolve, GatewayNotProvisioned, 1)

	g.step(10 * time.Second)
	g.resolver.err = errTest
	g.desire(t, "ns/b", testVPC1, "fd00::2")
	g.vrfs(t, 1, 0, 0, 0)
	g.ops(t, GatewayOpResolve, GatewayError, 1)

	g.resolver.err = nil
	g.resolver.addrs[testVPC1] = net.ParseIP("fd00:99::4")
	g.pub.publishErr = errTest
	g.desire(t, "ns/c", testVPC1, "fd00::3")
	g.vrfs(t, 0, 1, 0, 0)
	g.ops(t, GatewayOpResolve, GatewaySuccess, 1)
	g.ops(t, GatewayOpPublish, GatewayError, 1)

	g.pub.publishErr = nil
	g.desire(t, "ns/d", testVPC1, "fd00::4")
	g.vrfs(t, 0, 0, 1, -1)
	g.ops(t, GatewayOpPublish, GatewaySuccess, 1)
}

// TestGatewayOldestMovesToTheNext: with two VPCs waiting, publishing the
// older one makes the younger the oldest.
func TestGatewayOldestMovesToTheNext(t *testing.T) {
	g := newGatewayStore(t, true)
	g.desire(t, "ns/a", testVPC1, "fd00::1")
	g.step(30 * time.Second)
	g.desire(t, "ns/b", "vpc2", "fd00::2")
	g.vrfs(t, 2, 0, 0, 0)

	g.resolver.addrs[testVPC1] = net.ParseIP("fd00:99::4")
	g.desire(t, "ns/a2", testVPC1, "fd00::3")
	g.vrfs(t, 1, 0, 1, 30)
}

// TestGatewayDrainingVRFIsNotCounted: a VRF in its teardown grace period
// leaves the counts, and a failed withdrawal is counted while teardown goes
// on.
func TestGatewayDrainingVRFIsNotCounted(t *testing.T) {
	g := newGatewayStore(t, true)
	g.resolver.addrs[testVPC1] = net.ParseIP("fd00:99::4")
	g.desire(t, "ns/a", testVPC1, "fd00::1")
	g.vrfs(t, 0, 0, 1, -1)

	if err := g.SetDesired(context.Background(), "ns/a", nil); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	g.Sweep(context.Background(), start.Add(2*time.Minute)) // route removed; VRF starts draining
	g.vrfs(t, 0, 0, 0, -1)

	g.pub.withdrawErr = errTest
	g.Sweep(context.Background(), start.Add(5*time.Minute)) // VRF removed after a failed withdrawal
	g.ops(t, GatewayOpWithdraw, GatewayError, 1)
	if n := g.backend.vrfCount(); n != 0 {
		t.Errorf("%d VRFs left: a failed withdrawal must not block teardown", n)
	}
}

func TestGatewayMetricsNilIsInert(t *testing.T) {
	var m *GatewayMetrics
	m.operation(GatewayOpResolve, GatewaySuccess)
	m.publish(map[string]int{}, time.Now())
	_ = m.clock()
}

// TestSetGatewayMetricsCountsExistingVRFs: metrics set after VRFs exist
// count them.
func TestSetGatewayMetricsCountsExistingVRFs(t *testing.T) {
	backend := newFakeBackend()
	store := NewStore(backend, time.Minute, nil)
	store.SetGatewayPublisher(newFakeGatewayPublisher(), newFakeGatewayResolver())
	if err := store.SetDesired(context.Background(), "ns/a", &DesiredRoute{
		VPC: testVPC1, Prefix: mustPrefix(t, "fd00::1"), SID: net.ParseIP("fd00:99::1"),
	}); err != nil {
		t.Fatal(err)
	}
	m := NewGatewayMetrics(true, true)
	reg := prometheus.NewPedanticRegistry()
	m.MustRegister(reg)
	store.SetGatewayMetrics(m)
	if v := testutil.ToFloat64(m.vrfs.WithLabelValues(GatewayAwaitingAddress)); v != 1 {
		t.Errorf("gateway_vrfs{state=awaiting_address} = %v, want the existing VRF counted", v)
	}
}
