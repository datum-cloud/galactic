// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package runtime defines the RouterRuntime interface and RuntimeManager
// lifecycle abstractions for BGP backend implementations.
package runtime

import (
	"context"

	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

// RouterRuntime is the interface implemented by each BGP backend (GoBGP, FRR).
type RouterRuntime interface {
	// Apply converges the running BGP instance toward the given desired state.
	Apply(ctx context.Context, desired model.DesiredRouter) error

	// Status returns the current observed state of the runtime.
	Status(ctx context.Context) (model.RuntimeStatus, error)

	// Stop gracefully shuts down the runtime and releases its resources.
	Stop(ctx context.Context) error
}

// RuntimeFactory constructs a new RouterRuntime for the given BGPRouter key.
type RuntimeFactory func(key types.NamespacedName) (RouterRuntime, error)

// RuntimeManager owns the lifecycle of RouterRuntime instances, keyed by BGPRouter.
type RuntimeManager interface {
	// Apply converges the runtime for key toward desired, creating it if needed.
	Apply(ctx context.Context, key types.NamespacedName, desired model.DesiredRouter) error

	// Stop shuts down the runtime for key. No-op if no runtime exists.
	Stop(ctx context.Context, key types.NamespacedName) error

	// StopAll shuts down all managed runtimes.
	StopAll(ctx context.Context) error

	// Status returns the observed state of the runtime for key.
	// Returns an empty status (Healthy: false) if no runtime exists yet.
	Status(ctx context.Context, key types.NamespacedName) (model.RuntimeStatus, error)
}
