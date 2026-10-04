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

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeEgressTable stands in for egress_route_table. A gateway installs only
// once usable reports it, as Register succeeds only once the SID's uplink and
// neighbor resolve.
type fakeEgressTable struct {
	mu      sync.Mutex
	usable  map[string]bool
	entries map[vrfRouteKey]string
	adds    int
}

func newFakeEgressTable(t *testing.T) *fakeEgressTable {
	t.Helper()
	f := &fakeEgressTable{usable: make(map[string]bool), entries: make(map[vrfRouteKey]string)}

	prevAdd, prevDel, prevWatch := vrfRouteAdd, vrfRouteDel, watchMainRouteChanges
	t.Cleanup(func() {
		vrfRouteAdd, vrfRouteDel, watchMainRouteChanges = prevAdd, prevDel, prevWatch
	})

	vrfRouteAdd = func(prefix *net.IPNet, gw net.IP, tableID uint32) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.adds++
		if !f.usable[gw.String()] {
			return errors.New("no route to sid over an SRv6 uplink")
		}
		f.entries[vrfRouteKey{tableID: tableID, prefix: mustPrefixFromIPNet(t, prefix)}] = gw.String()
		return nil
	}
	vrfRouteDel = func(prefix *net.IPNet, tableID uint32) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.entries, vrfRouteKey{tableID: tableID, prefix: mustPrefixFromIPNet(t, prefix)})
		return nil
	}
	watchMainRouteChanges = func(context.Context) (<-chan struct{}, error) {
		return nil, errors.New("no subscription in tests")
	}
	return f
}

func (f *fakeEgressTable) setUsable(gw net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usable[gw.String()] = true
}

func (f *fakeEgressTable) entry(key vrfRouteKey) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	gw, ok := f.entries[key]
	return gw, ok
}

func (f *fakeEgressTable) addCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds
}

var (
	tenantRoute = vrfRouteKey{tableID: 42, prefix: netip.MustParsePrefix("2001:db8:100::/64")}
	tenantSID   = net.ParseIP("fc00:0:a:42::")
)

// TestVRFRoutes_RetriesFailedInstall is the regression test for #676: a route
// whose install failed while its uplink was unusable must be installed once
// it is, with no new BGP event.
func TestVRFRoutes_RetriesFailedInstall(t *testing.T) {
	f := newFakeEgressTable(t)
	var failing int
	v := newVRFRoutes(func(n int) { failing = n })

	v.install(tenantRoute, tenantSID)
	if _, ok := f.entry(tenantRoute); ok {
		t.Fatalf("route installed with no usable uplink")
	}
	if failing != 1 {
		t.Fatalf("failing = %d after a failed install, want 1", failing)
	}

	// Still unusable: retrying neither installs it nor double-counts it.
	v.retryPending()
	if failing != 1 {
		t.Fatalf("failing = %d after a failed retry, want 1", failing)
	}

	f.setUsable(tenantSID)
	v.retryPending()
	if gw, ok := f.entry(tenantRoute); !ok || gw != tenantSID.String() {
		t.Errorf("entry once the uplink is usable = %q (present %v), want %q", gw, ok, tenantSID)
	}
	if failing != 0 {
		t.Errorf("failing = %d after the retry succeeded, want 0", failing)
	}

	before := f.addCount()
	v.retryPending()
	if got := f.addCount(); got != before {
		t.Errorf("installed route retried again: %d adds, want %d", got, before)
	}
}

// TestVRFRoutes_WithdrawStopsRetry checks a pending route withdrawn before its
// uplink came up is not installed afterwards.
func TestVRFRoutes_WithdrawStopsRetry(t *testing.T) {
	f := newFakeEgressTable(t)
	var failing int
	v := newVRFRoutes(func(n int) { failing = n })

	v.install(tenantRoute, tenantSID)
	if err := v.withdraw(tenantRoute); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if failing != 0 {
		t.Errorf("failing = %d after withdraw, want 0", failing)
	}

	f.setUsable(tenantSID)
	v.retryPending()
	if _, ok := f.entry(tenantRoute); ok {
		t.Errorf("withdrawn route installed by a retry")
	}
}

// TestVRFRoutes_RetryUsesLatestGateway checks a pending route whose best path
// moved to another SID is retried toward the new one.
func TestVRFRoutes_RetryUsesLatestGateway(t *testing.T) {
	f := newFakeEgressTable(t)
	v := newVRFRoutes(nil)
	otherSID := net.ParseIP("fc00:0:b:42::")

	v.install(tenantRoute, tenantSID)
	v.install(tenantRoute, otherSID)
	f.setUsable(tenantSID)
	f.setUsable(otherSID)
	v.retryPending()
	if gw, _ := f.entry(tenantRoute); gw != otherSID.String() {
		t.Errorf("entry = %q, want the latest gateway %q", gw, otherSID)
	}
}

// TestVRFRoutes_ForgetTable checks removing a VRF drops its pending routes and
// leaves other VRFs' alone.
func TestVRFRoutes_ForgetTable(t *testing.T) {
	f := newFakeEgressTable(t)
	var failing int
	v := newVRFRoutes(func(n int) { failing = n })
	otherVRF := vrfRouteKey{tableID: 43, prefix: tenantRoute.prefix}

	v.install(tenantRoute, tenantSID)
	v.install(otherVRF, tenantSID)
	v.forgetTable(tenantRoute.tableID)
	if failing != 1 {
		t.Errorf("failing = %d after forgetting one of two VRFs, want 1", failing)
	}

	f.setUsable(tenantSID)
	v.retryPending()
	if _, ok := f.entry(tenantRoute); ok {
		t.Errorf("route for a removed VRF installed by a retry")
	}
	if _, ok := f.entry(otherVRF); !ok {
		t.Errorf("route for a remaining VRF not retried")
	}
}

// TestVRFRoutes_RunRetriesOnRouteChange drives run itself: a main-table change
// must retry pending routes without waiting for the timer.
func TestVRFRoutes_RunRetriesOnRouteChange(t *testing.T) {
	f := newFakeEgressTable(t)
	changes := make(chan struct{}, 1)
	watchMainRouteChanges = func(context.Context) (<-chan struct{}, error) { return changes, nil }

	v := newVRFRoutes(nil)
	v.retry = time.Hour
	v.debounce = time.Millisecond
	v.install(tenantRoute, tenantSID)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		v.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	f.setUsable(tenantSID)
	changes <- struct{}{}
	waitFor(t, func() bool {
		_, ok := f.entry(tenantRoute)
		return ok
	})
}

// TestInstallFailingReporter checks the gauge a reporter sets, per router and
// kind.
func TestInstallFailingReporter(t *testing.T) {
	const router = "test/installfailing"
	t.Cleanup(func() { routeInstallFailing.DeleteLabelValues(router, "vrf") })

	report := installFailingReporter(router, "vrf")
	if got := testutil.ToFloat64(routeInstallFailing.WithLabelValues(router, "vrf")); got != 0 {
		t.Errorf("gauge = %v before any report, want 0", got)
	}
	report(3)
	if got := testutil.ToFloat64(routeInstallFailing.WithLabelValues(router, "vrf")); got != 3 {
		t.Errorf("gauge = %v, want 3", got)
	}
}
