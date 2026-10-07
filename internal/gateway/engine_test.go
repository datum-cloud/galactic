// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// fakeDatapath is an in-memory Datapath for exercising Engine's
// convergence logic without a kernel or root privileges.
type fakeDatapath struct {
	applied            map[string]DesiredRule
	applyCalls         []string
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
	f.applyCalls = append(f.applyCalls, rule.Key)
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
	reserved   int
	deny       bool
	checkErr   error
	releaseErr error
	released   []string
}

func (f *fakeQuota) CheckAndReserve(context.Context, DesiredRule) (bool, error) {
	f.reserved++
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

func TestEngine_ReconcileSkipsUnchangedRule(t *testing.T) {
	dp := newFakeDatapath()
	quota := &fakeQuota{}
	tel := &fakeTelemetry{}
	e := NewEngine(dp, quota, tel)
	ctx := context.Background()
	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA, Port: 80}}}

	for i := range 3 {
		status, err := e.Reconcile(ctx, desired)
		if err != nil {
			t.Fatalf("Reconcile %d: %v", i, err)
		}
		if !status.Healthy || len(status.Rules) != 1 || !status.Rules[0].Applied || status.Rules[0].Key != testKeyA {
			t.Errorf("Reconcile %d status = %+v, want one healthy applied entry for %s", i, status, testKeyA)
		}
	}
	if len(dp.applyCalls) != 1 {
		t.Errorf("ApplyRule calls = %v, want exactly one for an unchanged rule", dp.applyCalls)
	}
	if quota.reserved != 1 {
		t.Errorf("quota reservations = %d, want 1", quota.reserved)
	}
	if len(tel.applied) != 1 {
		t.Errorf("RuleApplied events = %v, want 1", tel.applied)
	}
}

func TestEngine_ReconcileReappliesOnlyChangedRule(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()
	backend := func(usid string) []DesiredBackend {
		return []DesiredBackend{{
			Address: netip.MustParseAddr("2001:db8:1::10"), Port: 8080, USID: netip.MustParseAddr(usid),
		}}
	}
	ruleA := DesiredRule{Key: testKeyA, Port: 80, Backends: backend("fc00:0:1::")}
	ruleB := DesiredRule{Key: testKeyB, Port: 443, Backends: backend("fc00:0:1::")}

	first := EngineState{Rules: map[string]DesiredRule{testKeyA: ruleA, testKeyB: ruleB}}
	if _, err := e.Reconcile(ctx, first); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	dp.applyCalls = nil

	moved := ruleA
	moved.Backends = backend("fc00:0:2::")
	second := EngineState{Rules: map[string]DesiredRule{testKeyA: moved, testKeyB: ruleB}}
	if _, err := e.Reconcile(ctx, second); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if want := []string{testKeyA}; !slices.Equal(dp.applyCalls, want) {
		t.Errorf("ApplyRule calls = %v, want %v", dp.applyCalls, want)
	}
	if got := dp.applied[testKeyA].Backends[0].USID; got != netip.MustParseAddr("fc00:0:2::") {
		t.Errorf("applied backend uSID = %s, want fc00:0:2::", got)
	}
}

func TestEngine_ReconcileRetriesFailedRule(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()
	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}

	dp.applyErr = errors.New("simulated apply failure")
	if _, err := e.Reconcile(ctx, desired); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	dp.applyErr = nil
	if _, err := e.Reconcile(ctx, desired); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(dp.applyCalls) != 2 {
		t.Errorf("ApplyRule calls = %v, want a retry after the failed apply", dp.applyCalls)
	}
	if _, ok := dp.applied[testKeyA]; !ok {
		t.Error("rule not applied after the retry")
	}
}

func TestEngine_ReconcileRetriesActiveRuleAfterFailedUpdate(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()
	rule := DesiredRule{Key: testKeyA, Port: 80}
	changed := DesiredRule{Key: testKeyA, Port: 443}

	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{testKeyA: rule}}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	dp.applyErr = errors.New("simulated apply failure")
	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{testKeyA: changed}}); err != nil {
		t.Fatalf("failed update Reconcile: %v", err)
	}
	dp.applyErr = nil
	dp.applyCalls = nil

	// Reverting to the still-active rule must reapply it: the failed update
	// released its quota and may have left the datapath half-written.
	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{testKeyA: rule}}); err != nil {
		t.Fatalf("revert Reconcile: %v", err)
	}
	if want := []string{testKeyA}; !slices.Equal(dp.applyCalls, want) {
		t.Errorf("ApplyRule calls after revert = %v, want %v", dp.applyCalls, want)
	}

	dp.applyCalls = nil
	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{testKeyA: rule}}); err != nil {
		t.Fatalf("steady Reconcile: %v", err)
	}
	if len(dp.applyCalls) != 0 {
		t.Errorf("ApplyRule calls once clean = %v, want none", dp.applyCalls)
	}
}

func TestEngine_ReconcileReappliesRuleWhoseRemovalFailed(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()
	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA, Port: 80}}}

	if _, err := e.Reconcile(ctx, desired); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	dp.removeErr = errors.New("simulated teardown failure")
	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{}}); err != nil {
		t.Fatalf("failed removal Reconcile: %v", err)
	}
	dp.removeErr = nil
	dp.applyCalls = nil

	if _, err := e.Reconcile(ctx, desired); err != nil {
		t.Fatalf("return Reconcile: %v", err)
	}
	if want := []string{testKeyA}; !slices.Equal(dp.applyCalls, want) {
		t.Errorf("ApplyRule calls = %v, want %v after a failed removal", dp.applyCalls, want)
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

func TestEngine_ReconcileApplyErrorReleasesQuotaReservation(t *testing.T) {
	dp := newFakeDatapath()
	dp.applyErr = errors.New("simulated datapath failure")
	quota := &fakeQuota{}
	e := NewEngine(dp, quota, &fakeTelemetry{})

	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}
	if _, err := e.Reconcile(context.Background(), desired); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Reconcile never adds a failed key to e.active, so this is the only
	// chance the reservation ever gets to be released.
	if len(quota.released) != 1 || quota.released[0] != testKeyA {
		t.Errorf("quota.released = %v, want [%s] after a failed apply", quota.released, testKeyA)
	}
}

func TestEngine_ReconcileRemoveErrorKeepsRuleActiveAndReleasesQuota(t *testing.T) {
	dp := newFakeDatapath()
	quota := &fakeQuota{}
	e := NewEngine(dp, quota, &fakeTelemetry{})
	ctx := context.Background()

	if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}}}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	dp.removeErr = errors.New("simulated teardown failure")
	status, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{}})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if status.Healthy {
		t.Error("status.Healthy = true, want false (datapath teardown failed)")
	}
	if len(status.Rules) != 1 || !strings.Contains(status.Rules[0].Error, "simulated teardown failure") {
		t.Errorf("status.Rules = %+v, want one entry reporting the datapath error", status.Rules)
	}
	if len(quota.released) != 1 || quota.released[0] != testKeyA {
		t.Errorf("quota.released = %v, want [%s] even though datapath removal failed", quota.released, testKeyA)
	}

	// The key stays active so the next pass retries the datapath teardown.
	active, err := e.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(active.Rules) != 1 || active.Rules[0].Key != testKeyA {
		t.Errorf("Status() = %+v, want %q still active after a failed teardown", active, testKeyA)
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

func TestEngine_StopKeepsEveryFailedTeardownActive(t *testing.T) {
	dp := newFakeDatapath()
	e := NewEngine(dp, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()

	desired := EngineState{Rules: map[string]DesiredRule{testKeyA: {Key: testKeyA}, testKeyB: {Key: testKeyB}}}
	if _, err := e.Reconcile(ctx, desired); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	dp.removeErr = errors.New("simulated teardown failure")
	if err := e.Stop(ctx); err == nil {
		t.Fatal("Stop() = nil, want the first teardown error")
	}

	// Both teardowns failed, so neither may be dropped -- whichever key
	// map iteration reaches second must not fall through to the delete
	// just because the first one already set firstErr.
	status, err := e.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(status.Rules) != 2 {
		t.Errorf("Status() after a wholly-failed Stop = %+v, want both rules still active", status)
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
