// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

const (
	edgeTestNamespace = "galactic-system"
	edgeTestNode      = "node-a"
)

// fakeGates is one link's own address and gate deadlines.
type fakeGates struct {
	ifindex uint32
	addr    netip.Addr
	gates   map[netip.Prefix]time.Duration
	err     error
}

func (f *fakeGates) Close() error { return nil }

func (f *fakeGates) Open(ifindex uint32, addr netip.Addr, prefix netip.Prefix, now time.Duration) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if ifindex != f.ifindex || addr != f.addr {
		return false, nil
	}
	d, ok := f.gates[prefix]
	return ok && d > now, nil
}

func edgeAdvertisement(name, prefix, link, addr string) *bgpv1alpha1.BGPAdvertisement {
	return &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: edgeTestNamespace,
			Labels: map[string]string{crdnames.LabelEdgeRoute: "uid-" + name},
			Annotations: map[string]string{crdnames.AnnotationEdgeHostLink: link,
				crdnames.AnnotationEdgeAddress: addr}},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: "router-a"},
			Prefixes: []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(prefix)}},
	}
}

func router(name, node string) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: edgeTestNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Name: node}}}
}

// TestEdgeGate: an edge advertisement is open only when the host link it
// names is the edge link of the address it names and holds an unexpired
// gate for exactly its prefix.
func TestEdgeGate(t *testing.T) {
	now := 100 * time.Second
	table := &fakeGates{ifindex: 7, addr: netip.MustParseAddr("fd00:10:0:e::1"), gates: map[netip.Prefix]time.Duration{
		netip.MustParsePrefix("fd00:10:0:f::/80"):   now + time.Second,
		netip.MustParsePrefix("fd00:10:0:f:1::/80"): now,
	}}
	g := &edgeGate{openTable: func() (gateTable, error) { return table, nil },
		clock: func() time.Duration { return now }, now: time.Now,
		linkIndex: func(name string) (int, error) {
			if name == "gea" {
				return 7, nil
			}
			return 0, errors.New("no such link")
		}}
	twoPrefixes := edgeAdvertisement("two", "fd00:10:0:f::/80", "gea", "fd00:10:0:e::1")
	twoPrefixes.Spec.Prefixes = append(twoPrefixes.Spec.Prefixes, "fd00:10:0:f:2::/80")
	for _, tc := range []struct {
		name string
		adv  *bgpv1alpha1.BGPAdvertisement
		want bool
	}{
		{"open", edgeAdvertisement("a", "fd00:10:0:f::/80", "gea", "fd00:10:0:e::1"), true},
		{"expired", edgeAdvertisement("a", "fd00:10:0:f:1::/80", "gea", "fd00:10:0:e::1"), false},
		{"narrower than the gate", edgeAdvertisement("a", "fd00:10:0:f::/96", "gea", "fd00:10:0:e::1"), false},
		{"another address on the link", edgeAdvertisement("a", "fd00:10:0:f::/80", "gea", "fd00:10:0:e::2"), false},
		{"link absent", edgeAdvertisement("a", "fd00:10:0:f::/80", "geb", "fd00:10:0:e::1"), false},
		{"no link named", edgeAdvertisement("a", "fd00:10:0:f::/80", "", "fd00:10:0:e::1"), false},
		{"unmasked prefix", edgeAdvertisement("a", "fd00:10:0:f::1/80", "gea", "fd00:10:0:e::1"), false},
		{"two prefixes", twoPrefixes, false},
	} {
		if got := g.Open(tc.adv); got != tc.want {
			t.Errorf("%s: Open = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// toggleGate opens the advertisements it holds true.
type toggleGate struct {
	mu   sync.Mutex
	open map[string]bool
}

func (g *toggleGate) Open(adv *bgpv1alpha1.BGPAdvertisement) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open[adv.Name]
}

func (g *toggleGate) set(name string, open bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.open[name] = open
}

// TestEdgeGateWatch: the node's router is woken for each of its edge
// advertisements on the first poll, then only when one's gate opens or
// closes; another node's advertisements are not checked.
func TestEdgeGateWatch(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	plain := edgeAdvertisement("plain", "fd00:10:0:f:9::/80", "gea", "fd00:10:0:e::1")
	plain.Labels = nil
	other := edgeAdvertisement("other", "fd00:10:0:f:a::/80", "geo", "fd00:10:0:e::5")
	other.Spec.RouterRef.Name = "router-b"
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(edgeAdvertisement("a", "fd00:10:0:f::/80", "gea", "fd00:10:0:e::1"), plain, other,
			router("router-a", edgeTestNode), router("router-b", "node-b")).Build()
	gate := &toggleGate{open: map[string]bool{"other": true}}
	wake := make(chan event.GenericEvent, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = (&edgeGateWatch{client: c, nodeName: edgeTestNode, gate: gate, interval: time.Millisecond,
			wake: wake}).Start(ctx)
	}()

	expectWake := func(what string) {
		t.Helper()
		select {
		case e := <-wake:
			if e.Object.GetName() != "router-a" || e.Object.GetNamespace() != edgeTestNamespace {
				t.Fatalf("%s woke %s/%s", what, e.Object.GetNamespace(), e.Object.GetName())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not wake the router", what)
		}
	}
	expectQuiet := func(what string) {
		t.Helper()
		select {
		case <-wake:
			t.Fatalf("%s woke the router", what)
		case <-time.After(50 * time.Millisecond):
		}
	}
	expectWake("first poll")
	expectQuiet("unchanged gate")
	gate.set("a", true)
	expectWake("gate opened")
	expectQuiet("open gate")
	gate.set("a", false)
	expectWake("gate closed")
}

// deadlineGate is open until a deadline on the real clock, as a gate is.
type deadlineGate struct{ deadline time.Time }

func (g deadlineGate) Open(*bgpv1alpha1.BGPAdvertisement) bool { return time.Now().Before(g.deadline) }

// TestEdgeGateWatchDeadline: a gate's deadline passing, with no other
// event, wakes the router within one poll at the production interval.
func TestEdgeGateWatchDeadline(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(edgeAdvertisement("a", "fd00:10:0:f::/80", "gea", "fd00:10:0:e::1"),
			router("router-a", edgeTestNode)).Build()
	deadline := time.Now().Add(time.Second)
	wake := make(chan event.GenericEvent, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = (&edgeGateWatch{client: c, nodeName: edgeTestNode, gate: deadlineGate{deadline}, interval: edgeGatePoll,
			wake: wake}).Start(ctx)
	}()
	<-wake // the first poll
	select {
	case <-wake:
	case <-time.After(5 * time.Second):
		t.Fatal("the deadline passed without waking the router")
	}
	late := time.Since(deadline)
	t.Logf("router woken %v after the gate's deadline", late)
	if late < 0 || late > edgeGatePoll+100*time.Millisecond {
		t.Fatalf("router woken %v after the deadline, want within one %v poll", late, edgeGatePoll)
	}
}

// TestEdgeGateReopens: a gate map missing when the router starts, or one
// whose read fails, closes every edge route and is opened again, at most
// every gateReopen, so the router picks the gate up without a restart.
func TestEdgeGateReopens(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00:10:0:f::/80")
	table := &fakeGates{ifindex: 7, addr: netip.MustParseAddr("fd00:10:0:e::1"),
		gates: map[netip.Prefix]time.Duration{prefix: time.Hour}}
	wall := time.Unix(1000, 0)
	opens := 0
	pinned := false
	g := &edgeGate{
		openTable: func() (gateTable, error) {
			opens++
			if !pinned {
				return nil, errors.New("not pinned")
			}
			return table, nil
		},
		clock: func() time.Duration { return time.Second }, now: func() time.Time { return wall },
		linkIndex: func(string) (int, error) { return 7, nil },
	}
	adv := edgeAdvertisement("a", prefix.String(), "gea", "fd00:10:0:e::1")
	first := g.Open(adv)
	second := g.Open(adv)
	if first || second || opens != 1 {
		t.Fatalf("missing map: opened %d times, want closed and one attempt", opens)
	}
	pinned = true
	if g.Open(adv) {
		t.Fatal("opened again before gateReopen")
	}
	wall = wall.Add(gateReopen)
	if !g.Open(adv) || opens != 2 {
		t.Fatalf("map pinned later: not picked up (%d attempts)", opens)
	}
	table.err = errors.New("map replaced")
	if g.Open(adv) {
		t.Fatal("open after a failed read")
	}
	table.err = nil
	wall = wall.Add(gateReopen)
	if !g.Open(adv) || opens != 3 {
		t.Fatalf("map not reopened after a failed read (%d attempts)", opens)
	}
}
