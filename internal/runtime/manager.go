// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package runtime

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

type runtimeManager struct {
	mu       sync.RWMutex
	runtimes map[types.NamespacedName]RouterRuntime
	factory  RuntimeFactory
}

// NewRuntimeManager returns a RuntimeManager that creates RouterRuntime instances
// on demand using factory and manages their lifecycle.
func NewRuntimeManager(factory RuntimeFactory) RuntimeManager {
	return &runtimeManager{
		runtimes: make(map[types.NamespacedName]RouterRuntime),
		factory:  factory,
	}
}

func (m *runtimeManager) Apply(ctx context.Context, key types.NamespacedName, desired model.DesiredRouter) error {
	rt, err := m.getOrCreate(key)
	if err != nil {
		return fmt.Errorf("get or create runtime for %s: %w", key, err)
	}
	return rt.Apply(ctx, desired)
}

func (m *runtimeManager) Stop(ctx context.Context, key types.NamespacedName) error {
	m.mu.Lock()
	rt, ok := m.runtimes[key]
	if ok {
		delete(m.runtimes, key)
	}
	m.mu.Unlock()

	if !ok {
		return nil
	}
	return rt.Stop(ctx)
}

func (m *runtimeManager) StopAll(ctx context.Context) error {
	m.mu.Lock()
	rts := make(map[types.NamespacedName]RouterRuntime, len(m.runtimes))
	maps.Copy(rts, m.runtimes)
	m.runtimes = make(map[types.NamespacedName]RouterRuntime)
	m.mu.Unlock()

	var firstErr error
	for _, rt := range rts {
		if err := rt.Stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *runtimeManager) Status(ctx context.Context, key types.NamespacedName) (model.RuntimeStatus, error) {
	m.mu.RLock()
	rt, ok := m.runtimes[key]
	m.mu.RUnlock()

	if !ok {
		// No runtime yet — this is normal before the first successful Apply.
		// Return an empty status so the caller can distinguish "not yet applied"
		// from "applied but unhealthy".
		return model.RuntimeStatus{}, nil
	}
	return rt.Status(ctx)
}

func (m *runtimeManager) getOrCreate(key types.NamespacedName) (RouterRuntime, error) {
	m.mu.RLock()
	rt, ok := m.runtimes[key]
	m.mu.RUnlock()
	if ok {
		return rt, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Double-checked locking.
	if rt, ok = m.runtimes[key]; ok {
		return rt, nil
	}
	rt, err := m.factory(key)
	if err != nil {
		return nil, err
	}
	m.runtimes[key] = rt
	return rt, nil
}
