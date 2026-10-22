// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package claim

import (
	"context"
	"errors"
	"math/rand/v2"
	"strconv"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory Store. Before and after applying each operation it
// calls delay, which the simulation uses to model network latency during
// which simulated time passes.
type memStore struct {
	records map[string]Record
	next    int
	delay   func()
	down    func() bool
	// duringGet runs while a Get is in flight, before it reads the record.
	duringGet func()
	// loseReply makes the next Update apply and then report a timeout.
	loseReply bool
}

var errTimeout = errors.New("store reply lost")

// newMemStore starts with an explicitly released claim so tests of renewal and
// takeover can establish their first holder without a cold-start quarantine.
func newMemStore() *memStore {
	return &memStore{records: map[string]Record{
		"att": {Key: "att", Released: true, Version: "bootstrap", Incarnation: "bootstrap"},
	}}
}

var errUnreachable = errors.New("store unreachable")

func (s *memStore) around(fn func() (Record, error)) (Record, error) {
	if s.down != nil && s.down() {
		return Record{}, errUnreachable
	}
	if s.delay != nil {
		s.delay()
	}
	r, err := fn()
	if s.delay != nil {
		s.delay()
	}
	return r, err
}

func (s *memStore) Get(_ context.Context, key string) (Record, error) {
	return s.around(func() (Record, error) {
		if hook := s.duringGet; hook != nil {
			s.duringGet = nil
			hook()
		}
		r, ok := s.records[key]
		if !ok {
			return Record{}, ErrNotFound
		}
		return r, nil
	})
}

func (s *memStore) Create(_ context.Context, r Record) (Record, error) {
	return s.around(func() (Record, error) {
		if _, ok := s.records[r.Key]; ok {
			return Record{}, ErrConflict
		}
		s.next++
		r.Version = strconv.Itoa(s.next)
		s.records[r.Key] = r
		return r, nil
	})
}

func (s *memStore) Update(_ context.Context, r Record) (Record, error) {
	return s.around(func() (Record, error) {
		cur, ok := s.records[r.Key]
		if !ok {
			return Record{}, ErrNotFound
		}
		if cur.Version != r.Version {
			return Record{}, ErrConflict
		}
		s.next++
		r.Version = strconv.Itoa(s.next)
		s.records[r.Key] = r
		if s.loseReply {
			s.loseReply = false
			return Record{}, errTimeout
		}
		return r, nil
	})
}

var params = Params{Duration: 10 * time.Second, MaxDrift: 0.001, Margin: 100 * time.Millisecond, MaxSkew: time.Second}

// manualClock is a monotonic clock tests advance by hand.
type manualClock struct{ now time.Duration }

func (c *manualClock) read() time.Duration { return c.now }

func newInstance(id string, store Store, clock *manualClock) *Instance {
	return &Instance{ID: id, Store: store, Clock: clock.read, Params: params}
}

func TestAcquireRenewRelease(t *testing.T) {
	ctx := context.Background()
	store, clock := newMemStore(), &manualClock{}
	a := newInstance("a", store, clock)
	l, err := a.Acquire(ctx, "att")
	if err != nil {
		t.Fatal(err)
	}
	if l.Epoch != 1 || l.Deadline != params.Duration {
		t.Fatalf("first lease %+v", l)
	}
	clock.now += 4 * time.Second
	l, err = a.Renew(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	if l.Epoch != 1 || l.Deadline != 4*time.Second+params.Duration {
		t.Fatalf("renewed lease %+v", l)
	}
	if err := a.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	b := newInstance("b", store, clock)
	lb, err := b.Acquire(ctx, "att")
	if err != nil {
		t.Fatalf("acquire after acknowledged release: %v", err)
	}
	if lb.Epoch != 2 {
		t.Fatalf("replacement epoch %d, want 2", lb.Epoch)
	}
}

func TestTakeoverWaitsForUnchangedRecord(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	ca, cb := &manualClock{}, &manualClock{}
	a, b := newInstance("a", store, ca), newInstance("b", store, cb)
	la, err := a.Acquire(ctx, "att")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(ctx, "att"); !errors.Is(err, ErrHeld) {
		t.Fatalf("first observation = %v, want ErrHeld", err)
	}
	// The holder renews before the wait elapses, so the record changes and
	// the replacement's observation restarts.
	ca.now += 5 * time.Second
	cb.now += 5 * time.Second
	if la, err = a.Renew(ctx, la); err != nil {
		t.Fatal(err)
	}
	cb.now += params.TakeoverWait()
	if _, err := b.Acquire(ctx, "att"); !errors.Is(err, ErrHeld) {
		t.Fatalf("acquire after the record changed = %v, want ErrHeld", err)
	}
	// The holder is partitioned from now on.
	cb.now += params.TakeoverWait()
	lb, err := b.Acquire(ctx, "att")
	if err != nil {
		t.Fatalf("takeover after an unchanged wait: %v", err)
	}
	if lb.Epoch != la.Epoch+1 {
		t.Fatalf("takeover epoch %d, want %d", lb.Epoch, la.Epoch+1)
	}
	if _, err := a.Renew(ctx, la); !errors.Is(err, ErrLost) {
		t.Fatalf("old holder renew after takeover = %v, want ErrLost", err)
	}
	if err := a.Release(ctx, la); err != nil {
		t.Fatal(err)
	}
	r, _ := store.Get(ctx, "att")
	if r.Released || r.Holder != "b" {
		t.Fatalf("stale release changed the replacement's claim: %+v", r)
	}
}

func TestRestartedInstanceCannotReviveItsClaim(t *testing.T) {
	ctx := context.Background()
	store, clock := newMemStore(), &manualClock{}
	if _, err := newInstance("a", store, clock).Acquire(ctx, "att"); err != nil {
		t.Fatal(err)
	}
	restarted := newInstance("a", store, clock)
	if _, err := restarted.Acquire(ctx, "att"); !errors.Is(err, ErrHeld) {
		t.Fatalf("restarted instance acquire = %v, want ErrHeld", err)
	}
}

func TestCeilingCapsDeadline(t *testing.T) {
	ctx := context.Background()
	store, clock := newMemStore(), &manualClock{}
	wall := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	a := newInstance("a", store, clock)
	a.Wall = func() time.Time { return wall }
	a.Ceiling = wall.Add(4 * time.Second)
	l, err := a.Acquire(ctx, "att")
	if err != nil {
		t.Fatal(err)
	}
	if want := 4*time.Second - params.MaxSkew; l.Deadline != want {
		t.Fatalf("deadline %v, want %v (ceiling less skew)", l.Deadline, want)
	}
	wall = wall.Add(3 * time.Second)
	if _, err := a.Renew(ctx, l); !errors.Is(err, ErrCeiling) {
		t.Fatalf("renew past the ceiling = %v, want ErrCeiling", err)
	}
}

// simNode is one instance in the simulation, with its own drifting clock.
type simNode struct {
	inst  *Instance
	rate  float64
	lease *Lease
	cut   bool
}

// simulate runs random schedules of renewals, partitions and takeovers. The
// instances use p, while their clocks drift at up to drift and every store
// operation takes up to two seconds. It returns how many times two instances
// held valid leases at the same real instant, and how many takeovers
// happened without a release.
func simulate(seeds uint64, p Params, drift float64) (violations, takeovers int) {
	for seed := range seeds {
		rng := rand.New(rand.NewPCG(seed, 0x5eed))
		var real time.Duration
		store := newMemStore()
		var active *simNode
		store.delay = func() { real += time.Duration(rng.Int64N(int64(2 * time.Second))) }
		store.down = func() bool { return active != nil && active.cut }
		nodes := make([]*simNode, 3)
		for i := range nodes {
			n := &simNode{rate: 1 + drift*(2*rng.Float64()-1)}
			if i == 0 {
				n.rate = 1 - drift // the first holder's clock runs slowest
			}
			nodes[i] = n
			n.inst = &Instance{ID: "n" + strconv.Itoa(i), Store: store, Params: p, Clock: func() time.Duration {
				return time.Duration(float64(real) * n.rate)
			}}
		}
		valid := func(n *simNode) bool { return n.lease != nil && n.lease.Valid(n.inst.Clock()) }
		check := func() {
			holders := 0
			for _, n := range nodes {
				if valid(n) {
					holders++
				}
			}
			if holders > 1 {
				violations++
			}
		}
		epoch := uint64(0)
		for range 400 {
			n := nodes[rng.IntN(len(nodes))]
			active = n
			switch {
			case rng.IntN(20) == 0:
				delete(store.records, "att")
			case rng.IntN(10) == 0:
				n.cut = !n.cut
			case n.lease != nil:
				l, err := n.inst.Renew(context.Background(), *n.lease)
				switch {
				case err == nil:
					n.lease = &l
				case errors.Is(err, ErrLost):
					n.lease = nil
				}
			default:
				if l, err := n.inst.Acquire(context.Background(), "att"); err == nil {
					n.lease = &l
					if l.Epoch > 1 && l.Epoch > epoch {
						takeovers++
					}
					epoch = l.Epoch
				}
			}
			active = nil
			check()
			real += time.Duration(rng.Int64N(int64(6 * time.Second)))
			check()
		}
	}
	return violations, takeovers
}

// TestNoDualAuthorityUnderDriftAndDelay checks that, with clocks drifting by
// up to MaxDrift and slow store operations, no two instances ever hold a
// valid lease at the same real instant.
func TestNoDualAuthorityUnderDriftAndDelay(t *testing.T) {
	strong := params
	strong.MaxDrift = 0.05
	violations, takeovers := simulate(300, strong, strong.MaxDrift)
	if violations != 0 {
		t.Fatalf("%d instants with two valid leases", violations)
	}
	if takeovers < 100 {
		t.Fatalf("only %d takeovers happened; the simulation does not exercise takeover", takeovers)
	}
	t.Logf("%d takeovers, no dual authority", takeovers)
}

// worstCaseOverlap runs the tightest schedule for a takeover: the holder's
// clock runs slowest and the replacement's fastest, store operations take no
// time, the replacement first observes the record the instant the holder
// renewed it, and then polls every millisecond while the holder is cut off.
// It reports whether the holder's lease was still valid when the takeover
// succeeded.
func worstCaseOverlap(t *testing.T, p Params, drift float64) bool {
	t.Helper()
	var real time.Duration
	store := newMemStore()
	holder := &Instance{ID: "old", Store: store, Params: p, Clock: func() time.Duration {
		return time.Duration(float64(real) * (1 - drift))
	}}
	replacement := &Instance{ID: "new", Store: store, Params: p, Clock: func() time.Duration {
		return time.Duration(float64(real) * (1 + drift))
	}}
	l, err := holder.Acquire(context.Background(), "att")
	if err != nil {
		t.Fatal(err)
	}
	for real < 10*p.Duration {
		if _, err := replacement.Acquire(context.Background(), "att"); err == nil {
			return l.Valid(holder.Clock())
		}
		real += time.Millisecond
	}
	t.Fatal("takeover never happened")
	return false
}

// TestWorstCaseTakeoverWaitsForHolderDeadline checks the takeover bound on the
// tightest schedule, and that the same schedule does overlap when instances
// assume less drift than their clocks have, so the bound is what prevents it.
func TestWorstCaseTakeoverWaitsForHolderDeadline(t *testing.T) {
	const drift = 0.05
	correct := params
	correct.MaxDrift, correct.Margin = drift, 0
	if worstCaseOverlap(t, correct, drift) {
		t.Fatal("takeover succeeded while the holder's lease was still valid")
	}
	understated := correct
	understated.MaxDrift = 0
	if !worstCaseOverlap(t, understated, drift) {
		t.Fatal("understated drift produced no overlap; the schedule does not exercise the bound")
	}
}

// TestRenewalDuringSlowReadDelaysTakeover covers a holder renewal that lands
// while the replacement's read is in flight: the replacement's wait must
// start when the read returned, not when it was sent.
func TestRenewalDuringSlowReadDelaysTakeover(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	var real time.Duration
	clock := func() time.Duration { return real }
	p := params
	p.MaxDrift, p.Margin = 0, 0
	holder := &Instance{ID: "old", Store: store, Clock: clock, Params: p}
	replacement := &Instance{ID: "new", Store: store, Clock: clock, Params: p}
	l, err := holder.Acquire(ctx, "att")
	if err != nil {
		t.Fatal(err)
	}
	store.duringGet = func() {
		real += 5 * time.Second
		if l, err = holder.Renew(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := replacement.Acquire(ctx, "att"); !errors.Is(err, ErrHeld) {
		t.Fatalf("first observation = %v, want ErrHeld", err)
	}
	for real < 3*p.Duration {
		if _, err := replacement.Acquire(ctx, "att"); err == nil {
			if l.Valid(real) {
				t.Fatalf("takeover at %v while the holder's lease runs to %v", real, l.Deadline)
			}
			return
		}
		real += 10 * time.Millisecond
	}
	t.Fatal("takeover never happened")
}

// TestRenewRecoversFromLostReply covers a renewal the store applied whose
// reply never arrived.
func TestRenewRecoversFromLostReply(t *testing.T) {
	ctx := context.Background()
	store, clock := newMemStore(), &manualClock{}
	a := newInstance("a", store, clock)
	l, err := a.Acquire(ctx, "att")
	if err != nil {
		t.Fatal(err)
	}
	store.loseReply = true
	clock.now += time.Second
	kept, err := a.Renew(ctx, l)
	if !errors.Is(err, errTimeout) || kept != l {
		t.Fatalf("renew with lost reply = %+v, %v; want the old lease and the timeout", kept, err)
	}
	clock.now += time.Second
	renewed, err := a.Renew(ctx, kept)
	if err != nil {
		t.Fatalf("renew after a lost reply: %v", err)
	}
	if renewed.Epoch != l.Epoch || renewed.Deadline != clock.now+params.Duration {
		t.Fatalf("recovered lease %+v, want epoch %d and deadline %v", renewed, l.Epoch, clock.now+params.Duration)
	}
}

func TestCeilingWithoutWallClockIsRejected(t *testing.T) {
	a := newInstance("a", newMemStore(), &manualClock{})
	a.Ceiling = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if _, err := a.Acquire(context.Background(), "att"); err == nil {
		t.Fatal("acquire with a ceiling and no wall clock succeeded")
	}
}

func TestDeletedClaimWaitsBeforeRecreation(t *testing.T) {
	ctx := t.Context()
	store, clock := newMemStore(), &manualClock{}
	old := newInstance("old", store, clock)
	lease, err := old.Acquire(ctx, "att")
	if err != nil {
		t.Fatal(err)
	}
	delete(store.records, "att")
	replacement := newInstance("new", store, clock)
	if _, err := replacement.Acquire(ctx, "att"); !errors.Is(err, ErrHeld) {
		t.Fatalf("missing record granted authority: %v", err)
	}
	clock.now = params.Duration / 2
	if !lease.Valid(clock.now) {
		t.Fatal("test must retain old authority")
	}
	if _, err := replacement.Acquire(ctx, "att"); !errors.Is(err, ErrHeld) {
		t.Fatalf("early takeover: %v", err)
	}
	clock.now = params.TakeoverWait()
	next, err := replacement.Acquire(ctx, "att")
	if err != nil {
		t.Fatal(err)
	}
	if lease.Valid(clock.now) {
		t.Fatal("dual authority")
	}
	if next.Incarnation == lease.Incarnation || next.Incarnation == "" {
		t.Fatal("record identity reused")
	}
	if err := old.Release(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if store.records["att"].Released {
		t.Fatal("stale release changed new incarnation")
	}
}

func TestRepeatedDeletionRestartsQuarantine(t *testing.T) {
	ctx := t.Context()
	store, clock := newMemStore(), &manualClock{}
	delete(store.records, "att")
	in := newInstance("holder", store, clock)
	if _, err := in.Acquire(ctx, "att"); !errors.Is(err, ErrHeld) {
		t.Fatal(err)
	}
	first := store.records["att"].Incarnation
	clock.now = params.TakeoverWait()
	delete(store.records, "att")
	if _, err := in.Acquire(ctx, "att"); !errors.Is(err, ErrHeld) {
		t.Fatalf("recreated record skipped wait: %v", err)
	}
	if store.records["att"].Incarnation == first {
		t.Fatal("reused incarnation")
	}
	clock.now += params.TakeoverWait()
	if _, err := in.Acquire(ctx, "att"); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredLeaseCannotRenew(t *testing.T) {
	store, clock := newMemStore(), &manualClock{}
	in := newInstance("holder", store, clock)
	lease, err := in.Acquire(t.Context(), "att")
	if err != nil {
		t.Fatal(err)
	}
	before := store.records["att"]
	clock.now = lease.Deadline
	if _, err := in.Renew(t.Context(), lease); !errors.Is(err, ErrLost) {
		t.Fatalf("expired renewal: %v", err)
	}
	if store.records["att"] != before {
		t.Fatal("expired renewal mutated record")
	}
}

func TestConcurrentAcquire(t *testing.T) {
	// All calls use one instance, whose mutex also serializes this test store.
	store := newMemStore()
	delete(store.records, "att")
	in := &Instance{ID: "holder", Store: store, Params: params, Clock: func() time.Duration { return 0 }}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := in.Acquire(t.Context(), "att"); !errors.Is(err, ErrHeld) {
				t.Errorf("cold acquire: %v", err)
			}
		})
	}
	wg.Wait()
	if len(in.observed) != 1 {
		t.Fatalf("observations = %d", len(in.observed))
	}
}
