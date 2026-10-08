// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrQueueFull is returned when the cell's request queue is at its bound.
var ErrQueueFull = errors.New("cell execution queue is full")

// Executor is the cell-wide budget for node RPCs, shared by every concurrent
// request. It grants at most Slots RPCs at once, at most ExpensiveSlots of
// them expensive searches, so searches can never occupy every slot. Waiters
// queue per project and are served round-robin across projects, FIFO within
// one, so one project's burst cannot starve another. The queue is bounded;
// a full queue refuses at once rather than letting waits outlive requests.
type Executor struct {
	slots, expSlots, maxQueue int

	mu      sync.Mutex
	inUse   int
	expUse  int
	waiting int
	queues  map[string][]*waiter
	ring    []string
	next    int

	// ObserveWait, when set, receives how long each granted waiter waited.
	ObserveWait func(time.Duration)
}

type waiter struct {
	expensive bool
	ready     chan struct{}
	granted   bool
	queued    time.Time
}

// NewExecutor returns an Executor. Zero values select 8 slots, 2 expensive
// slots and a queue of 256.
func NewExecutor(slots, expensiveSlots, maxQueue int) *Executor {
	if slots <= 0 {
		slots = 8
	}
	if expensiveSlots <= 0 {
		expensiveSlots = 2
	}
	expensiveSlots = min(expensiveSlots, slots)
	if maxQueue <= 0 {
		maxQueue = 256
	}
	return &Executor{slots: slots, expSlots: expensiveSlots, maxQueue: maxQueue, queues: map[string][]*waiter{}}
}

// Acquire waits for a slot for project until ctx ends. The returned function
// releases it.
func (e *Executor) Acquire(ctx context.Context, project string, expensive bool) (func(), error) {
	e.mu.Lock()
	if e.waiting >= e.maxQueue {
		e.mu.Unlock()
		return nil, ErrQueueFull
	}
	w := &waiter{expensive: expensive, ready: make(chan struct{}), queued: time.Now()}
	if len(e.queues[project]) == 0 {
		e.ring = append(e.ring, project)
	}
	e.queues[project] = append(e.queues[project], w)
	e.waiting++
	e.dispatchLocked()
	e.mu.Unlock()

	release := func() {
		e.mu.Lock()
		e.inUse--
		if w.expensive {
			e.expUse--
		}
		e.dispatchLocked()
		e.mu.Unlock()
	}
	select {
	case <-w.ready:
		if e.ObserveWait != nil {
			e.ObserveWait(time.Since(w.queued))
		}
		return release, nil
	case <-ctx.Done():
		e.mu.Lock()
		if w.granted {
			e.mu.Unlock()
			release()
		} else {
			e.removeLocked(project, w)
			e.mu.Unlock()
		}
		return nil, ctx.Err()
	}
}

// Depth returns the number of queued waiters.
func (e *Executor) Depth() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.waiting
}

// dispatchLocked grants free slots to eligible waiters, round-robin across
// projects.
func (e *Executor) dispatchLocked() {
	for e.inUse < e.slots && len(e.ring) > 0 {
		granted := false
		for i := range len(e.ring) {
			idx := (e.next + i) % len(e.ring)
			project := e.ring[idx]
			for _, w := range e.queues[project] {
				if w.expensive && e.expUse >= e.expSlots {
					continue
				}
				w.granted = true
				e.inUse++
				if w.expensive {
					e.expUse++
				}
				close(w.ready)
				e.removeLocked(project, w)
				// Start after this project next time, accounting for its
				// removal from the ring if it emptied.
				if _, still := e.queues[project]; still {
					e.next = (idx + 1) % len(e.ring)
				} else if len(e.ring) > 0 {
					e.next = idx % len(e.ring)
				}
				granted = true
				break
			}
			if granted {
				break
			}
		}
		if !granted {
			return
		}
	}
}

func (e *Executor) removeLocked(project string, w *waiter) {
	q := e.queues[project]
	for i, x := range q {
		if x == w {
			e.queues[project] = append(q[:i], q[i+1:]...)
			e.waiting--
			break
		}
	}
	if len(e.queues[project]) == 0 {
		delete(e.queues, project)
		for i, p := range e.ring {
			if p == project {
				e.ring = append(e.ring[:i], e.ring[i+1:]...)
				if e.next > i {
					e.next--
				}
				break
			}
		}
		if len(e.ring) == 0 {
			e.next = 0
		} else {
			e.next %= len(e.ring)
		}
	}
}
