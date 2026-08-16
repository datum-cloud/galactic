// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

const testNamespace = "default"

// fakeRuntime is a minimal RouterRuntime test double that records whether
// Stop was called and can be configured to return an error from it.
type fakeRuntime struct {
	mu      sync.Mutex
	stopped bool
	stopErr error
}

func (f *fakeRuntime) Apply(_ context.Context, _ model.DesiredRouter) error { return nil }

func (f *fakeRuntime) Status(_ context.Context) (model.RuntimeStatus, error) {
	return model.RuntimeStatus{}, nil
}

func (f *fakeRuntime) Stop(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	return f.stopErr
}

func (f *fakeRuntime) wasStopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped
}

func TestRuntimeManagerStopAll(t *testing.T) {
	keys := []types.NamespacedName{
		{Namespace: testNamespace, Name: "router-a"},
		{Namespace: testNamespace, Name: "router-b"},
	}
	runtimes := map[types.NamespacedName]*fakeRuntime{}

	mgr := NewRuntimeManager(func(key types.NamespacedName) (RouterRuntime, error) {
		rt := &fakeRuntime{}
		runtimes[key] = rt
		return rt, nil
	})

	ctx := context.Background()
	for _, key := range keys {
		if err := mgr.Apply(ctx, key, model.DesiredRouter{}); err != nil {
			t.Fatalf("Apply(%s): %v", key, err)
		}
	}

	if err := mgr.StopAll(ctx); err != nil {
		t.Fatalf("StopAll() returned error: %v", err)
	}

	for _, key := range keys {
		if !runtimes[key].wasStopped() {
			t.Errorf("runtime %s: Stop was not called by StopAll", key)
		}
	}

	// A runtime created after StopAll should not appear "already stopped" --
	// StopAll only affects runtimes that existed at the time it was called.
	newKey := types.NamespacedName{Namespace: testNamespace, Name: "router-c"}
	if err := mgr.Apply(ctx, newKey, model.DesiredRouter{}); err != nil {
		t.Fatalf("Apply(%s) after StopAll: %v", newKey, err)
	}
	if runtimes[newKey].wasStopped() {
		t.Errorf("runtime %s: Stop was called even though it was created after StopAll", newKey)
	}
}

func TestRuntimeManagerStopAllReturnsFirstError(t *testing.T) {
	wantErr := errors.New("stop failed")
	key := types.NamespacedName{Namespace: testNamespace, Name: "router-a"}

	mgr := NewRuntimeManager(func(types.NamespacedName) (RouterRuntime, error) {
		return &fakeRuntime{stopErr: wantErr}, nil
	})

	ctx := context.Background()
	if err := mgr.Apply(ctx, key, model.DesiredRouter{}); err != nil {
		t.Fatalf("Apply(%s): %v", key, err)
	}

	if err := mgr.StopAll(ctx); !errors.Is(err, wantErr) {
		t.Errorf("StopAll() error = %v, want %v", err, wantErr)
	}
}

func TestRuntimeManagerStopAllEmpty(t *testing.T) {
	mgr := NewRuntimeManager(func(types.NamespacedName) (RouterRuntime, error) {
		t.Fatal("factory should not be called when no runtime was ever created")
		return nil, nil
	})

	if err := mgr.StopAll(context.Background()); err != nil {
		t.Fatalf("StopAll() on empty manager returned error: %v", err)
	}
}
