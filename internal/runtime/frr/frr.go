// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package frr provides a stub FRR RouterRuntime implementation.
// NOTE: The fabric role is not yet implemented. Running galactic-router
// with ROUTER_ROLE=fabric will fail on the first reconcile.
package frr

import (
	"context"
	"errors"

	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/runtime"
)

var errNotImplemented = errors.New("frr runtime not implemented")

type frrRuntime struct{}

func (f *frrRuntime) Apply(_ context.Context, _ model.DesiredRouter) error {
	return errNotImplemented
}

func (f *frrRuntime) Status(_ context.Context) (model.RuntimeStatus, error) {
	return model.RuntimeStatus{}, errNotImplemented
}

func (f *frrRuntime) Stop(_ context.Context) error {
	return nil
}

// NewRuntimeFactory returns a RuntimeFactory that creates stub FRR runtimes.
func NewRuntimeFactory() runtime.RuntimeFactory {
	return func(_ types.NamespacedName) (runtime.RouterRuntime, error) {
		return &frrRuntime{}, nil
	}
}
