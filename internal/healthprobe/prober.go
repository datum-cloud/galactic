// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package healthprobe probes NetworkService backends from their own node and
// damps the results into one health decision per backend.
package healthprobe

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"
)

// Target is one backend to probe: Addr on Port, over the host-side interface
// Interface, with Config's timing and thresholds.
type Target struct {
	Interface string
	Addr      netip.Addr
	Port      uint16
	Config    Config
}

// DialFunc sends one probe. Dial is the production implementation.
type DialFunc func(ctx context.Context, iface string, addr netip.Addr, port uint16, timeout time.Duration) error

// Prober runs one probe loop per target and keeps its decision. Callers
// register interest in a target under an owner name, and Prober calls notify
// with an owner's name whenever its target's decision changes. A target with
// no owner left stops being probed.
//
// A target is named by an ID the caller chooses. Two owners with the same ID
// share one loop and one decision, so the ID must change whenever anything that
// should start the backend's decision over changes.
type Prober struct {
	ctx    context.Context
	dial   DialFunc
	notify func(owner string)
	now    func() time.Time

	mu      sync.Mutex
	targets map[string]*probeLoop
	owners  map[string]string // owner -> target ID
}

// probeLoop is one target's goroutine and decision.
type probeLoop struct {
	target  Target
	cancel  context.CancelFunc
	tracker *Tracker
	owners  map[string]bool
}

// NewProber returns a Prober whose loops run until ctx ends. notify is called
// from a loop's goroutine and must not block for long.
func NewProber(ctx context.Context, dial DialFunc, notify func(owner string)) *Prober {
	return &Prober{
		ctx:     ctx,
		dial:    dial,
		notify:  notify,
		now:     time.Now,
		targets: make(map[string]*probeLoop),
		owners:  make(map[string]string),
	}
}

// Ensure registers owner's interest in target under id and returns the
// target's current decision. The first owner of id starts its loop, from seed
// when seed is not nil. An owner that moves to a different id releases the
// old one.
func (p *Prober) Ensure(owner, id string, target Target, seed *Decision) Decision {
	p.mu.Lock()
	defer p.mu.Unlock()
	if prev, ok := p.owners[owner]; ok && prev != id {
		p.releaseLocked(owner)
	}
	loop, ok := p.targets[id]
	if !ok {
		ctx, cancel := context.WithCancel(p.ctx)
		loop = &probeLoop{
			target:  target,
			cancel:  cancel,
			tracker: NewTracker(target.Config, seed, p.now()),
			owners:  make(map[string]bool),
		}
		p.targets[id] = loop
		go p.run(ctx, loop)
	}
	loop.owners[owner] = true
	p.owners[owner] = id
	return loop.tracker.Decision()
}

// Release drops owner's interest, stopping its target's loop when no owner is
// left.
func (p *Prober) Release(owner string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseLocked(owner)
}

func (p *Prober) releaseLocked(owner string) {
	id, ok := p.owners[owner]
	if !ok {
		return
	}
	delete(p.owners, owner)
	loop := p.targets[id]
	delete(loop.owners, owner)
	if len(loop.owners) == 0 {
		loop.cancel()
		delete(p.targets, id)
	}
}

// run probes loop's target every interval, starting after a random part of
// one interval so that targets added together do not probe in step.
func (p *Prober) run(ctx context.Context, loop *probeLoop) {
	interval := loop.target.Config.Interval
	timer := time.NewTimer(rand.N(interval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		dialCtx, cancel := context.WithTimeout(ctx, loop.target.Config.Timeout)
		err := p.dial(dialCtx, loop.target.Interface, loop.target.Addr, loop.target.Port, loop.target.Config.Timeout)
		cancel()
		if ctx.Err() != nil {
			return
		}
		p.observe(loop, err)
		timer.Reset(interval)
	}
}

// observe records one result and notifies loop's owners if the decision
// changed.
func (p *Prober) observe(loop *probeLoop, err error) {
	p.mu.Lock()
	changed := loop.tracker.Observe(err, p.now())
	var owners []string
	if changed {
		for o := range loop.owners {
			owners = append(owners, o)
		}
	}
	p.mu.Unlock()
	for _, o := range owners {
		p.notify(o)
	}
}
