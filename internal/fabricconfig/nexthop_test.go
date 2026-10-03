// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
)

// Neighbors as `show bgp neighbors json` reports them: one session with the
// mapped next hop from datum-cloud/galactic#665, one healthy IPv6 session, an
// IPv4 session, one not yet established, and one sourced from a link-local
// address.
const neighborsJSON = `{
  "2607:f740:0:3f::39b": {
    "bgpState": "Established",
    "hostLocal": "2600:9c07:0:48::2",
    "nexthop": "188.42.80.235",
    "nexthopGlobal": "::ffff:188.42.80.235",
    "nexthopLocal": "::"
  },
  "fd00::ffff:1": {
    "bgpState": "Established",
    "hostLocal": "2600:9c07:0:48::2",
    "nexthop": "188.42.80.235",
    "nexthopGlobal": "2600:9c07:0:48::2",
    "nexthopLocal": "::"
  },
  "10.1.30.1": {
    "bgpState": "Established",
    "hostLocal": "10.1.30.2",
    "nexthop": "10.1.30.2",
    "nexthopGlobal": "::ffff:10.1.30.2",
    "nexthopLocal": "::"
  },
  "fd00::ffff:2": {
    "bgpState": "Active",
    "hostLocal": "Unknown",
    "nexthop": "Unknown",
    "nexthopGlobal": "Unknown",
    "nexthopLocal": "Unknown"
  },
  "fe80::1": {
    "bgpState": "Established",
    "hostLocal": "fe80::2",
    "nexthop": "188.42.80.235",
    "nexthopGlobal": "::ffff:188.42.80.235",
    "nexthopLocal": "fe80::2"
  }
}`

const mappedPeer = "2607:f740:0:3f::39b"

// Routes as `show ipv6 route json` reports them: the uninstalled route from
// datum-cloud/galactic#665, an installed BGP route, a BGP route that loses to
// an installed static route, and a connected route.
const routesJSON = `{
  "2607:ed40:10d::1:0:1/128": [
    {"protocol": "bgp", "selected": true, "distance": 200}
  ],
  "fc00:0:5::/48": [
    {"protocol": "bgp", "selected": true, "installed": true, "distance": 200}
  ],
  "fc00:0:4::/48": [
    {"protocol": "static", "selected": true, "installed": true, "distance": 1},
    {"protocol": "bgp", "distance": 200}
  ],
  "2600:9c07:0:48::/64": [
    {"protocol": "connected", "selected": true, "installed": true}
  ]
}`

type fakeBGP struct {
	neighbors   string
	routes      string
	neighborErr error
	resetErr    error
	resets      []string
}

func (f *fakeBGP) Neighbors(context.Context) ([]byte, error) {
	if f.neighborErr != nil {
		return nil, f.neighborErr
	}
	return []byte(f.neighbors), nil
}

func (f *fakeBGP) Routes(context.Context, string) ([]byte, error) {
	return []byte(f.routes), nil
}

func (f *fakeBGP) ResetNeighbor(_ context.Context, neighbor string) error {
	f.resets = append(f.resets, neighbor)
	return f.resetErr
}

func newTestGuard(bgp *fakeBGP) (*NextHopGuard, *events.FakeRecorder, *time.Time) {
	now := time.Date(2026, 10, 2, 14, 25, 0, 0, time.UTC)
	rec := events.NewFakeRecorder(10)
	g := &NextHopGuard{
		BGP:      bgp,
		Metrics:  NewNextHopMetrics(),
		Recorder: rec,
		Pod:      &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "fabric-router-abcde", Namespace: testNamespace}},
		NodeName: "edge-1",
		now:      func() time.Time { return now },
	}
	return g, rec, &now
}

func TestNextHopGuardResetsMappedSession(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON}
	g, rec, _ := newTestGuard(bgp)

	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(bgp.resets) != 1 || bgp.resets[0] != mappedPeer {
		t.Fatalf("resets = %v, want [%s]", bgp.resets, mappedPeer)
	}
	select {
	case e := <-rec.Events:
		if !strings.Contains(e, ReasonMappedNextHopReset) || !strings.Contains(e, mappedPeer) {
			t.Errorf("event = %q, want %s for %s", e, ReasonMappedNextHopReset, mappedPeer)
		}
	default:
		t.Error("no event recorded")
	}
	if got := testutil.ToFloat64(g.Metrics.mapped.WithLabelValues(mappedPeer)); got != 1 {
		t.Errorf("mapped{%s} = %v, want 1", mappedPeer, got)
	}
	if got := testutil.ToFloat64(g.Metrics.mapped.WithLabelValues("fd00::ffff:1")); got != 0 {
		t.Errorf("mapped{fd00::ffff:1} = %v, want 0", got)
	}
	// Only the two established sessions sourced from a global IPv6 address
	// are reported; the IPv4, down and link-local sessions are not.
	if got := testutil.CollectAndCount(g.Metrics.mapped); got != 2 {
		t.Errorf("mapped series = %d, want 2", got)
	}
	if got := testutil.ToFloat64(g.Metrics.resets.WithLabelValues(mappedPeer)); got != 1 {
		t.Errorf("resets{%s} = %v, want 1", mappedPeer, got)
	}
}

func TestNextHopGuardBacksOffRepeatedResets(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON}
	g, _, now := newTestGuard(bgp)
	g.ResetBackoff = 10 * time.Minute
	ctx := context.Background()

	for _, step := range []struct {
		advance time.Duration
		want    int
	}{
		{0, 1},
		{time.Minute, 1},
		{5 * time.Minute, 1},
		{5 * time.Minute, 2},
	} {
		*now = now.Add(step.advance)
		if err := g.Check(ctx); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(bgp.resets) != step.want {
			t.Fatalf("after %v: resets = %d, want %d", step.advance, len(bgp.resets), step.want)
		}
	}
}

func TestNextHopGuardDetectOnly(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON}
	g, _, _ := newTestGuard(bgp)
	g.DetectOnly = true

	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(bgp.resets) != 0 {
		t.Errorf("resets = %v, want none", bgp.resets)
	}
	if got := testutil.ToFloat64(g.Metrics.mapped.WithLabelValues(mappedPeer)); got != 1 {
		t.Errorf("mapped{%s} = %v, want 1", mappedPeer, got)
	}
}

func TestNextHopGuardClearsRecoveredSession(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON}
	g, _, _ := newTestGuard(bgp)
	ctx := context.Background()
	if err := g.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}

	bgp.neighbors = strings.Replace(neighborsJSON, `"nexthopGlobal": "::ffff:188.42.80.235",
    "nexthopLocal": "::"
  },
  "fd00::ffff:1"`, `"nexthopGlobal": "2600:9c07:0:48::2",
    "nexthopLocal": "::"
  },
  "fd00::ffff:1"`, 1)
	if err := g.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := testutil.ToFloat64(g.Metrics.mapped.WithLabelValues(mappedPeer)); got != 0 {
		t.Errorf("mapped{%s} = %v after recovery, want 0", mappedPeer, got)
	}
	if len(bgp.resets) != 1 {
		t.Errorf("resets = %d, want 1", len(bgp.resets))
	}
}

func TestNextHopGuardCountsUninstalledRoutes(t *testing.T) {
	bgp := &fakeBGP{neighbors: "{}", routes: routesJSON}
	g, _, _ := newTestGuard(bgp)

	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, afi := range []string{afiIPv4, afiIPv6} {
		if got := testutil.ToFloat64(g.Metrics.uninstalled.WithLabelValues(afi)); got != 1 {
			t.Errorf("uninstalled{%s} = %v, want 1", afi, got)
		}
	}
}

func TestNextHopGuardReportsReadErrors(t *testing.T) {
	bgp := &fakeBGP{neighborErr: errors.New("bgpd is not running"), routes: routesJSON}
	g, _, _ := newTestGuard(bgp)

	if err := g.Check(context.Background()); err == nil {
		t.Fatal("Check: want error, got nil")
	}
	// The route count still runs after the neighbor read fails.
	if got := testutil.ToFloat64(g.Metrics.uninstalled.WithLabelValues(afiIPv6)); got != 1 {
		t.Errorf("uninstalled{ipv6} = %v, want 1", got)
	}
}

func TestNextHopGuardResetFailureRaisesNoEvent(t *testing.T) {
	bgp := &fakeBGP{neighbors: neighborsJSON, routes: routesJSON, resetErr: errors.New("vtysh failed")}
	g, rec, _ := newTestGuard(bgp)

	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	select {
	case e := <-rec.Events:
		t.Errorf("unexpected event %q for a failed reset", e)
	default:
	}
	if got := testutil.ToFloat64(g.Metrics.resets.WithLabelValues(mappedPeer)); got != 0 {
		t.Errorf("resets{%s} = %v, want 0", mappedPeer, got)
	}
}
