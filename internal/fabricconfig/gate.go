// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"sync"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// SourceGate holds the node's effective configuration source. The
// deployment agent sets it; the ConfigMap agent writes FRR only while it is
// not CRD.
type SourceGate struct {
	mu      sync.Mutex
	source  networkv1alpha1.FabricConfigSource
	version int64
	changed chan struct{}
	// handoff is the ConfigMap UID the last handoff from CRD named.
	handoff string
}

// NewSourceGate starts at source.
func NewSourceGate(source networkv1alpha1.FabricConfigSource) *SourceGate {
	return &SourceGate{source: source, changed: make(chan struct{}, 1)}
}

// Get returns the source and a version that changes with it.
func (g *SourceGate) Get() (networkv1alpha1.FabricConfigSource, int64) {
	if g == nil {
		return networkv1alpha1.FabricConfigSourceConfigMap, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.source, g.version
}

// Set changes the source and wakes the ConfigMap agent.
func (g *SourceGate) Set(source networkv1alpha1.FabricConfigSource) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if source == g.source {
		return
	}
	g.source = source
	g.version++
	select {
	case g.changed <- struct{}{}:
	default:
	}
}

// SetHandoff records the ConfigMap UID a handoff from CRD names; the
// ConfigMap agent applies only that ConfigMap after the handoff.
func (g *SourceGate) SetHandoff(uid string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.handoff = uid
}

// Handoff returns the ConfigMap UID the last handoff named, empty for none.
func (g *SourceGate) Handoff() string {
	if g == nil {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.handoff
}

// Changed delivers a value after each change; nil for a nil gate.
func (g *SourceGate) Changed() <-chan struct{} {
	if g == nil {
		return nil
	}
	return g.changed
}
