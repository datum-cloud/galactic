// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"testing"
)

func TestEngine_ReconcileOrphansDelegatesToDatapath(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})

	var gotLive []DesiredRule
	var gotCutoff uint64
	dp.reconcileOrphansFn = func(_ context.Context, live []DesiredRule, cutoff uint64) error {
		gotLive = live
		gotCutoff = cutoff
		return nil
	}

	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}
	if err := e.ReconcileOrphans(context.Background(), desired, 99); err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}

	if gotCutoff != 99 {
		t.Errorf("cutoff passed to Datapath.ReconcileOrphans = %d, want 99", gotCutoff)
	}
	if len(gotLive) != 1 || gotLive[0].Key != testKeyA {
		t.Errorf("live passed to Datapath.ReconcileOrphans = %+v, want one rule %q", gotLive, testKeyA)
	}
}

func TestEngine_ReconcileOrphansPropagatesDatapathError(t *testing.T) {
	dp := newFakeDatapath()
	wantErr := errors.New("simulated reconcile failure")
	dp.reconcileOrphansFn = func(context.Context, []DesiredRule, uint64) error { return wantErr }

	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	err := e.ReconcileOrphans(context.Background(), EngineState{}, 0)
	if !errors.Is(err, wantErr) {
		t.Errorf("ReconcileOrphans error = %v, want it to wrap %v", err, wantErr)
	}
}

// TestEngine_ReconcileOrphansDoesNotConsultActiveMap confirms
// ReconcileOrphans works from desired alone (not e.active), matching its
// crash-recovery contract: e.active is empty immediately after a
// crash/restart, exactly when this method is needed.
func TestEngine_ReconcileOrphansDoesNotConsultActiveMap(t *testing.T) {
	dp := newFakeDatapath()
	var gotLive []DesiredRule
	dp.reconcileOrphansFn = func(_ context.Context, live []DesiredRule, _ uint64) error {
		gotLive = live
		return nil
	}

	// A fresh Engine: e.active is empty, never populated by Reconcile.
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})

	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}
	if err := e.ReconcileOrphans(context.Background(), desired, 0); err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}
	if len(gotLive) != 1 {
		t.Errorf("live = %+v, want the rule from desired regardless of e.active", gotLive)
	}
}
