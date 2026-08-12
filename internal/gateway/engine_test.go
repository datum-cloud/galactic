// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"testing"
)

// fakeDatapath is an in-memory Datapath for exercising Engine's
// convergence logic without a kernel or root privileges.
type fakeDatapath struct {
	applied            map[string]DesiredRule
	removed            []string
	applyErr           error
	removeErr          error
	generation         uint64
	reconcileOrphansFn func(context.Context, []DesiredRule, uint64) error
}

func newFakeDatapath() *fakeDatapath {
	return &fakeDatapath{applied: make(map[string]DesiredRule)}
}

func (f *fakeDatapath) ApplyRule(_ context.Context, rule DesiredRule) error {
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applied[rule.Key] = rule
	return nil
}

func (f *fakeDatapath) RemoveRule(_ context.Context, key string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.applied, key)
	f.removed = append(f.removed, key)
	return nil
}

func (f *fakeDatapath) Generation() uint64 { return f.generation }

func (f *fakeDatapath) ReconcileOrphans(ctx context.Context, live []DesiredRule, cutoff uint64) error {
	if f.reconcileOrphansFn != nil {
		return f.reconcileOrphansFn(ctx, live, cutoff)
	}
	return nil
}

var _ Datapath = (*fakeDatapath)(nil)

// fakeQuota is a controllable QuotaEnforcer.
type fakeQuota struct {
	deny       bool
	checkErr   error
	releaseErr error
	released   []string
}

func (f *fakeQuota) CheckAndReserve(context.Context, DesiredRule) (bool, error) {
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return !f.deny, nil
}

func (f *fakeQuota) Release(_ context.Context, key string) error {
	if f.releaseErr != nil {
		return f.releaseErr
	}
	f.released = append(f.released, key)
	return nil
}

var _ QuotaEnforcer = (*fakeQuota)(nil)

// fakeTelemetry records every call for assertion.
type fakeTelemetry struct {
	applied []string
	removed []string
	dropped []string
}

func (f *fakeTelemetry) RuleApplied(_ context.Context, rule DesiredRule) {
	f.applied = append(f.applied, rule.Key)
}
func (f *fakeTelemetry) RuleRemoved(_ context.Context, key string) {
	f.removed = append(f.removed, key)
}
func (f *fakeTelemetry) DropObserved(_ context.Context, key, _ string) {
	f.dropped = append(f.dropped, key)
}

var _ TelemetryEmitter = (*fakeTelemetry)(nil)

func TestEngine_ReconcileAppliesNewRules(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})

	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}
	status, err := e.Reconcile(context.Background(), desired)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !status.Healthy {
		t.Errorf("status.Healthy = false, want true; rules=%+v", status.Rules)
	}
	if _, ok := dp.applied[testKeyA]; !ok {
		t.Error("rule was not applied to the datapath")
	}
}

func TestEngine_ReconcileRemovesDroppedRules(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()

	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{}}); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}

	if _, ok := dp.applied[testKeyA]; ok {
		t.Error("rule still applied after being dropped from desired state")
	}
	if len(dp.removed) != 1 || dp.removed[0] != testKeyA {
		t.Errorf("dp.removed = %v, want [%s]", dp.removed, testKeyA)
	}
}

func TestEngine_ReconcileIsIdempotentAcrossRepeatedCalls(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()
	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}

	for range 3 {
		if _, err := e.Reconcile(ctx, desired); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	if len(dp.applied) != 1 {
		t.Errorf("applied = %v, want exactly one entry after repeated identical reconciles", dp.applied)
	}
}

func TestEngine_ReconcileQuotaDeniedSkipsApply(t *testing.T) {
	dp := newFakeDatapath()
	telem := &fakeTelemetry{}
	e := NewEngine(dp, &fakeQuota{deny: true}, telem)

	status, err := e.Reconcile(context.Background(), EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if status.Healthy {
		t.Error("status.Healthy = true, want false (quota denied)")
	}
	if _, ok := dp.applied[testKeyA]; ok {
		t.Error("rule was applied to the datapath despite quota denial")
	}
	if len(telem.dropped) != 1 || telem.dropped[0] != testKeyA {
		t.Errorf("telemetry.dropped = %v, want [%s]", telem.dropped, testKeyA)
	}
}

func TestEngine_ReconcileApplyErrorReportsUnhealthyKeepsGoing(t *testing.T) {
	dp := newFakeDatapath()
	dp.applyErr = errors.New("simulated datapath failure")
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})

	status, err := e.Reconcile(context.Background(), EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if status.Healthy {
		t.Error("status.Healthy = true, want false")
	}
	if len(status.Rules) != 1 || status.Rules[0].Error == "" {
		t.Errorf("status.Rules = %+v, want one entry with a non-empty Error", status.Rules)
	}
}

func TestEngine_StatusReflectsActiveRulesWithoutReconciling(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()

	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	status, err := e.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Healthy || len(status.Rules) != 1 || status.Rules[0].Key != testKeyA {
		t.Errorf("Status() = %+v, want one healthy rule %q", status, testKeyA)
	}
}

func TestEngine_StopTearsDownEveryActiveRule(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()

	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}, testKeyB: {Key: testKeyB}}}
	if _, err := e.Reconcile(ctx, desired); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if err := e.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if len(dp.applied) != 0 {
		t.Errorf("dp.applied = %v, want empty after Stop", dp.applied)
	}

	status, err := e.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(status.Rules) != 0 {
		t.Errorf("Status() after Stop = %+v, want no active rules", status)
	}
}

func TestEngine_DatapathGenerationDelegates(t *testing.T) {
	dp := newFakeDatapath()
	dp.generation = 12345
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})

	if got := e.DatapathGeneration(); got != 12345 {
		t.Errorf("DatapathGeneration() = %d, want 12345", got)
	}
}
