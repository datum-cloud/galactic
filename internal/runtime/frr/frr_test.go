// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package frr

import (
	"context"
	"testing"

	"go.datum.net/galactic/internal/model"
	"k8s.io/apimachinery/pkg/types"
)

func TestApplyReturnsErrNotImplemented(t *testing.T) {
	r := &frrRuntime{}
	err := r.Apply(context.Background(), model.DesiredRouter{})
	if err != errNotImplemented {
		t.Errorf("Apply() = %v, want errNotImplemented", err)
	}
}

func TestStatusReturnsEmptyAndErrNotImplemented(t *testing.T) {
	r := &frrRuntime{}
	status, err := r.Status(context.Background())
	if err != errNotImplemented {
		t.Errorf("Status() error = %v, want errNotImplemented", err)
	}
	if status.Healthy {
		t.Errorf("Status() Healthy = true, want false")
	}
	if len(status.Peers) != 0 {
		t.Errorf("Status() Peers = %d, want 0", len(status.Peers))
	}
	if len(status.Advertisements) != 0 {
		t.Errorf("Status() Advertisements = %d, want 0", len(status.Advertisements))
	}
}

func TestStopReturnsNil(t *testing.T) {
	r := &frrRuntime{}
	if err := r.Stop(context.Background()); err != nil {
		t.Errorf("Stop() = %v, want nil", err)
	}
}

func TestNewRuntimeFactory(t *testing.T) {
	factory := NewRuntimeFactory()
	runtime, err := factory(types.NamespacedName{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}
	if runtime == nil {
		t.Fatal("factory() returned nil runtime")
	}
	if _, ok := runtime.(*frrRuntime); !ok {
		t.Errorf("factory() returned %T, want *frrRuntime", runtime)
	}
}
