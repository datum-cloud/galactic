// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package healthprobe

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDial answers every probe with the error in result and counts probes.
type fakeDial struct {
	mu     sync.Mutex
	result error
	probes atomic.Int64
}

func (f *fakeDial) set(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result = err
}

func (f *fakeDial) dial(context.Context, string, netip.Addr, uint16, time.Duration) error {
	f.probes.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result
}

// notifications collects the owners a Prober notifies.
type notifications struct {
	ch chan string
}

func newNotifications() *notifications { return &notifications{ch: make(chan string, 64)} }

func (n *notifications) notify(owner string) { n.ch <- owner }

// next returns the owners notified for the next change, sorted, waiting at
// most a few seconds for them.
func (n *notifications) next(t *testing.T, count int) []string {
	t.Helper()
	var got []string
	timeout := time.After(5 * time.Second)
	for len(got) < count {
		select {
		case o := <-n.ch:
			got = append(got, o)
		case <-timeout:
			t.Fatalf("notified %v, want %d owners", got, count)
		}
	}
	sort.Strings(got)
	return got
}

func testTarget() Target {
	return Target{
		Interface: "veth0",
		Addr:      netip.MustParseAddr("fd20::100"),
		Port:      80,
		Config: Config{
			Interval: time.Millisecond, Timeout: time.Millisecond,
			UnhealthyThreshold: 2, HealthyThreshold: 2,
		},
	}
}

// TestProberSharesOneLoopPerID: owners of one ID share its decision, and both
// are notified when it changes.
func TestProberSharesOneLoopPerID(t *testing.T) {
	ctx := t.Context()
	dial := &fakeDial{}
	n := newNotifications()
	p := NewProber(ctx, dial.dial, n.notify)

	p.Ensure("binding-v6", "backend-1", testTarget(), nil)
	if d := p.Ensure("binding-v4", "backend-1", testTarget(), nil); d.State != StateUnknown {
		t.Fatalf("initial decision = %+v, want Unknown", d)
	}
	if got := n.next(t, 2); got[0] != "binding-v4" || got[1] != "binding-v6" {
		t.Fatalf("notified %v, want both owners", got)
	}
	if d := p.Ensure("binding-v6", "backend-1", testTarget(), nil); d.State != StateHealthy {
		t.Fatalf("decision = %+v, want Healthy", d)
	}

	dial.set(errRefused)
	n.next(t, 2)
	if d := p.Ensure("binding-v4", "backend-1", testTarget(), nil); d.State != StateUnhealthy {
		t.Fatalf("decision = %+v, want Unhealthy", d)
	}
}

// TestProberSeed: a loop started from a seed reports it until the results
// change it.
func TestProberSeed(t *testing.T) {
	ctx := t.Context()
	dial := &fakeDial{result: errRefused}
	p := NewProber(ctx, dial.dial, func(string) {})
	target := testTarget()
	target.Config.Interval = time.Hour

	seed := &Decision{State: StateUnhealthy, Reason: ReasonProbeFailed, Message: "refused"}
	if d := p.Ensure("b", "backend-1", target, seed); d != *seed {
		t.Errorf("decision = %+v, want the seed %+v", d, *seed)
	}
}

// TestProberReleaseStopsTheLoop: once its last owner is released a target is
// no longer probed, and a later owner starts it over from its own seed.
func TestProberReleaseStopsTheLoop(t *testing.T) {
	ctx := t.Context()
	dial := &fakeDial{}
	n := newNotifications()
	p := NewProber(ctx, dial.dial, n.notify)

	p.Ensure("a", "backend-1", testTarget(), nil)
	p.Ensure("b", "backend-1", testTarget(), nil)
	n.next(t, 2)

	p.Release("a")
	before := dial.probes.Load()
	waitForProbes(t, dial, before+3) // b still holds it

	p.Release("b")
	p.mu.Lock()
	_, running := p.targets["backend-1"]
	p.mu.Unlock()
	if running {
		t.Error("backend-1 still has a loop after its last owner was released")
	}

	if d := p.Ensure("c", "backend-1", testTarget(), nil); d.State != StateUnknown {
		t.Errorf("restarted decision = %+v, want Unknown", d)
	}
}

// TestProberOwnerMovesToAnotherID: an owner whose target changes releases the
// old one.
func TestProberOwnerMovesToAnotherID(t *testing.T) {
	ctx := t.Context()
	dial := &fakeDial{}
	p := NewProber(ctx, dial.dial, func(string) {})

	p.Ensure("a", "backend-1", testTarget(), nil)
	p.Ensure("a", "backend-2", testTarget(), nil)

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.targets["backend-1"]; ok {
		t.Error("backend-1 still has a loop after its only owner moved")
	}
	if _, ok := p.targets["backend-2"]; !ok {
		t.Error("backend-2 has no loop")
	}
}

func waitForProbes(t *testing.T, dial *fakeDial, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for dial.probes.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("probes = %d, want at least %d", dial.probes.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}
