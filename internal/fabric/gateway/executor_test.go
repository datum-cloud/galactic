// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestExecutorBoundsSlots(t *testing.T) {
	e := NewExecutor(2, 1, 10)
	r1, err := e.Acquire(context.Background(), "p", false)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := e.Acquire(context.Background(), "p", false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := e.Acquire(ctx, "p", false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("third acquire: %v", err)
	}
	if e.Depth() != 0 {
		t.Errorf("abandoned waiter left in queue")
	}
	r1()
	r3, err := e.Acquire(context.Background(), "p", false)
	if err != nil {
		t.Fatal(err)
	}
	r2()
	r3()
}

func TestExecutorExpensiveCannotTakeEverySlot(t *testing.T) {
	e := NewExecutor(3, 1, 10)
	rel, err := e.Acquire(context.Background(), "p", true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := e.Acquire(ctx, "p", true); err == nil {
		t.Fatal("second expensive search granted past the expensive budget")
	}
	// Cheap work still gets the remaining slots, even queued behind an
	// expensive waiter.
	go func() { _, _ = e.Acquire(context.Background(), "q", true) }()
	cheap, err := e.Acquire(context.Background(), "q", false)
	if err != nil {
		t.Fatal(err)
	}
	cheap()
	rel()
}

func TestExecutorFairAcrossProjects(t *testing.T) {
	e := NewExecutor(1, 1, 100)
	hold, _ := e.Acquire(context.Background(), "init", false)

	var mu sync.Mutex
	var order []string
	var wg sync.WaitGroup
	enqueue := func(p string) {
		wg.Go(func() {
			rel, err := e.Acquire(context.Background(), p, false)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			order = append(order, p)
			mu.Unlock()
			rel()
		})
	}
	// Project A floods the queue before B arrives.
	for range 5 {
		enqueue("a")
	}
	waitDepth(t, e, 5)
	enqueue("b")
	waitDepth(t, e, 6)
	hold()
	wg.Wait()

	pos := -1
	for i, p := range order {
		if p == "b" {
			pos = i
		}
	}
	if pos < 0 || pos > 1 {
		t.Errorf("order = %v; project b should be served within the first two grants", order)
	}
}

func TestExecutorQueueBound(t *testing.T) {
	e := NewExecutor(1, 1, 1)
	hold, _ := e.Acquire(context.Background(), "p", false)
	go func() { _, _ = e.Acquire(context.Background(), "p", false) }()
	waitDepth(t, e, 1)
	if _, err := e.Acquire(context.Background(), "q", false); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("err = %v", err)
	}
	hold()
}

func waitDepth(t *testing.T, e *Executor, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.Depth() != n {
		if time.Now().After(deadline) {
			t.Fatalf("depth %d, want %d", e.Depth(), n)
		}
		time.Sleep(time.Millisecond)
	}
}
