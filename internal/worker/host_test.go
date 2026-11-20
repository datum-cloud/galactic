// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/worker/hostscope"
	"go.datum.net/galactic/internal/worker/module"
)

// fakeHostState is an in-memory hostscope.Host: a VPC is present while it
// has a VRF, and referenced while it has links.
type fakeHostState struct {
	mu        sync.Mutex
	vrfs      map[string]bool
	links     map[string]int
	inPlace   map[string]bool
	ensures   map[string]int
	reclaims  map[string]int
	reclaimed []string
}

func newFakeHostState() *fakeHostState {
	return &fakeHostState{vrfs: map[string]bool{}, links: map[string]int{}, inPlace: map[string]bool{},
		ensures: map[string]int{}, reclaims: map[string]int{}}
}

func (f *fakeHostState) Discover(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.vrfs))
	for v := range f.vrfs {
		out = append(out, v)
	}
	slices.Sort(out)
	return out, nil
}

func (f *fakeHostState) Plan(_ context.Context, vpc string, claimed bool) (hostscope.Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := hostscope.Plan{Present: f.vrfs[vpc], Ensure: claimed && !f.inPlace[vpc]}
	for i := range f.links[vpc] {
		p.Links = append(p.Links, vpc+"-link"+string(rune('0'+i)))
	}
	return p, nil
}

func (f *fakeHostState) Ensure(_ context.Context, vpc string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensures[vpc]++
	f.vrfs[vpc], f.inPlace[vpc] = true, true
	return nil
}

func (f *fakeHostState) Reclaim(_ context.Context, vpc string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reclaims[vpc]++
	if f.links[vpc] > 0 {
		return false, nil
	}
	delete(f.vrfs, vpc)
	delete(f.inPlace, vpc)
	f.reclaimed = append(f.reclaimed, vpc)
	return true, nil
}

func (f *fakeHostState) Attachments(context.Context, string) ([]hostscope.Attachment, error) {
	return nil, nil
}

func (f *fakeHostState) set(vpc string, links int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vrfs[vpc], f.links[vpc], f.inPlace[vpc] = true, links, true
}

func (f *fakeHostState) counts(vpc string) (ensures, reclaims int, present bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ensures[vpc], f.reclaims[vpc], f.vrfs[vpc]
}

func hostEnv(t *testing.T) (*env, *fakeHostState) {
	t.Helper()
	e := newEnv(t)
	h := newFakeHostState()
	e.hostState = h
	e.cfg.HostGrace = 50 * time.Millisecond
	return e, h
}

func (e *env) fenceOwner(vpc string) ownership.Record {
	e.t.Helper()
	rec, err := e.fence.Read(module.Scope{VPC: vpc}.Name())
	if err != nil {
		e.t.Fatal(err)
	}
	return rec
}

// TestHostAdoptsDiscoveredScopes takes every VPC scope found on the host with
// a snapshot that writes nothing, leaving a scope another writer owns alone.
func TestHostAdoptsDiscoveredScopes(t *testing.T) {
	e, h := hostEnv(t)
	h.set(vpcA, 1)
	h.set(vpcB, 1)
	tk, err := e.fence.Claim(module.Scope{VPC: vpcB}.Name(), "galactic-edge:node-a:1")
	e.mustOK(err)
	_, err = e.fence.CommitSnapshot(tk, func() error { return nil })
	e.mustOK(err)

	e.start()
	e.eventually("vpcA adopted", func() bool {
		r := e.fenceOwner(vpcA)
		return r.Owner == e.w.Owner() && !r.Pending
	})
	e.idle()
	if r := e.fenceOwner(vpcB); r.Owner != "galactic-edge:node-a:1" {
		t.Fatalf("scope another writer owns = %+v", r)
	}
	for _, v := range []string{vpcA, vpcB} {
		if ens, rec, present := h.counts(v); ens != 0 || rec != 0 || !present {
			t.Fatalf("%s: ensures %d, reclaims %d, present %t; adoption must write nothing", v, ens, rec, present)
		}
	}

	// A restart takes the scope over from the earlier incarnation.
	before := e.fenceOwner(vpcA)
	e.crash()
	e.start()
	e.eventually("vpcA taken over", func() bool {
		r := e.fenceOwner(vpcA)
		return r.Owner == e.w.Owner() && !r.Pending && r.Generation > before.Generation
	})
}

// TestHostReclaimsAfterGrace reclaims a VPC's host state only once it has
// gone unused for the grace, and never while a link or claim uses it.
func TestHostReclaimsAfterGrace(t *testing.T) {
	e, h := hostEnv(t)
	h.set(vpcA, 1)
	e.start()
	e.idle()

	// A claim keeps the state after the last link goes.
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(mkey(vpcA, "svc-a"), 1)
	h.set(vpcA, 0)
	e.w.HostChanged(vpcA)
	e.clock.Advance(time.Hour)
	time.Sleep(3 * e.cfg.HostGrace)
	e.idle()
	if _, rec, present := h.counts(vpcA); rec != 0 || !present {
		t.Fatalf("reclaims %d, present %t while a claim uses the VPC", rec, present)
	}

	// Released: unused from now, reclaimed once the grace passes.
	e.mustOK(e.release(natSA, key(vpcA, "svc-a"), 1))
	e.waitGone(mkey(vpcA, "svc-a"))
	e.w.HostChanged(vpcA)
	e.idle()
	if _, rec, _ := h.counts(vpcA); rec != 0 {
		t.Fatalf("reclaimed before the grace")
	}
	e.clock.Advance(time.Minute)
	e.eventually("vpcA reclaimed", func() bool {
		_, _, present := h.counts(vpcA)
		return !present
	})
	e.idle()
	e.w.mu.Lock()
	_, tracked := e.w.scopes[vpcA]
	e.w.mu.Unlock()
	if tracked {
		t.Fatal("scope still tracked after its VRF was reclaimed")
	}
}

// TestHostEnsuredForClaims ensures the VPC's canonical state for a claim when
// it is missing, and not again while it is in place.
func TestHostEnsuredForClaims(t *testing.T) {
	e, h := hostEnv(t)
	e.start()
	e.mustOK(e.request(natSA, key(vpcB, "svc-b"), 1, veth("guest-b1")))
	e.waitReady(mkey(vpcB, "svc-b"), 1)
	e.idle()
	ens, _, present := h.counts(vpcB)
	if ens == 0 || !present {
		t.Fatalf("ensures %d, present %t; want the state ensured for the claim", ens, present)
	}
	e.w.Changed(vpcB)
	e.idle()
	if again, _, _ := h.counts(vpcB); again != ens {
		t.Fatalf("ensured again (%d → %d) with the state in place", ens, again)
	}
}

// TestHostTakesHandedBackScope checks that a Worker installed again after a
// handback (internal/worker/handback) takes back the scopes no legacy writer
// took in between, with a snapshot, and leaves one a legacy writer took.
func TestHostTakesHandedBackScope(t *testing.T) {
	e, h := hostEnv(t)
	h.set(vpcA, 1)
	h.set(vpcB, 1)
	e.start()
	e.eventually("both scopes adopted", func() bool {
		return e.fenceOwner(vpcA).Owner == e.w.Owner() && e.fenceOwner(vpcB).Owner == e.w.Owner()
	})
	e.idle()
	e.crash()
	label := ownership.HandbackOwnerPrefix + "20261119T120000Z"
	for _, v := range []string{vpcA, vpcB} {
		if _, err := e.fence.Relinquish(module.Scope{VPC: v}.Name(), func(r ownership.Record) bool {
			return ownership.WorkerOwned(r.Owner)
		}, label); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.fence.Takeover(module.Scope{VPC: vpcB}.Name(), "galactic-edge:node-a:2",
		func(r ownership.Record) bool { return ownership.HandedBack(r.Owner) }); err != nil {
		t.Fatal(err)
	}

	e.start()
	e.eventually("vpcA taken back", func() bool {
		r := e.fenceOwner(vpcA)
		return r.Owner == e.w.Owner() && !r.Pending
	})
	e.idle()
	if r := e.fenceOwner(vpcB); r.Owner != "galactic-edge:node-a:2" {
		t.Fatalf("a scope galactic-edge took after the handback = %+v", r)
	}
}
