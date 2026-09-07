// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Engine is the in-process gateway engine on one gateway node: a
// mutex-protected map of currently active state, converged toward a desired
// state on each Reconcile. It holds no VRF state, this datapath having no VRF
// dependency.
type Engine struct {
	mu     sync.Mutex
	active map[string]DesiredRule

	datapath  Datapath
	quota     QuotaEnforcer
	telemetry TelemetryEmitter
}

// NewEngine returns an Engine wired to the given implementations. Production
// callers pass the kernel datapath and the real quota and telemetry
// implementations; tests pass fakes.
func NewEngine(datapath Datapath, quota QuotaEnforcer, telemetry TelemetryEmitter) *Engine {
	return &Engine{
		active:    make(map[string]DesiredRule),
		datapath:  datapath,
		quota:     quota,
		telemetry: telemetry,
	}
}

// Reconcile converges live state toward desired: every rule in desired is
// re-applied, and every rule still active but no longer in desired is torn
// down. The caller must already have withdrawn a rule's BGP route before it
// disappears from desired.
//
// It applies everything in desired and removes everything not in it, rather
// than diffing field by field, so a partial previous failure, such as a crash
// between two rules, self-heals on the next call instead of requiring the
// caller to track what succeeded.
func (e *Engine) Reconcile(ctx context.Context, desired EngineState) (EngineStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	toApply, toRemove := diffRuleKeys(e.active, desired.Rules)

	var statuses []RuleStatus
	for _, key := range toApply {
		rule := desired.Rules[key]
		if err := e.applyRuleLocked(ctx, rule); err != nil {
			statuses = append(statuses, RuleStatus{Key: key, Applied: false, Error: err.Error()})
			continue
		}
		e.active[key] = rule
		statuses = append(statuses, RuleStatus{Key: key, Applied: true})
	}

	for _, key := range toRemove {
		if err := e.removeRuleLocked(ctx, key); err != nil {
			statuses = append(statuses, RuleStatus{Key: key, Applied: true, Error: err.Error()})
			continue
		}
		delete(e.active, key)
	}

	healthy := true
	for _, s := range statuses {
		if s.Error != "" {
			healthy = false
			break
		}
	}
	return EngineStatus{Healthy: healthy, Rules: statuses}, nil
}

// Status returns the current observed state without performing a
// convergence pass, mirroring RouterRuntime.Status.
func (e *Engine) Status(context.Context) (EngineStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	statuses := make([]RuleStatus, 0, len(e.active))
	for key := range e.active {
		statuses = append(statuses, RuleStatus{Key: key, Applied: true})
	}
	return EngineStatus{Healthy: true, Rules: statuses}, nil
}

// Stop tears down every currently active rule. The caller must already have
// withdrawn BGP routes for every one, exactly as for an individual removal.
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var firstErr error
	for key := range e.active {
		// A key whose teardown failed stays active whether or not an
		// earlier key already failed; only the first error is returned.
		if err := e.removeRuleLocked(ctx, key); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("stop: remove rule %s: %w", key, err)
			}
			continue
		}
		delete(e.active, key)
	}
	return firstErr
}

// DatapathGeneration returns a snapshot of the underlying datapath's monotonic
// clock. A caller intending to call ReconcileOrphans must read it before
// listing the CRDs that become that call's live set.
func (e *Engine) DatapathGeneration() uint64 {
	return e.datapath.Generation()
}

// applyRuleLocked performs the real (quota-gated Datapath.ApplyRule) work
// for a single rule. Caller must hold e.mu.
func (e *Engine) applyRuleLocked(ctx context.Context, rule DesiredRule) error {
	ok, err := e.quota.CheckAndReserve(ctx, rule)
	if err != nil {
		return fmt.Errorf("quota check for %s: %w", rule.Key, err)
	}
	if !ok {
		e.telemetry.DropObserved(ctx, rule.Key, "quota_exceeded")
		return fmt.Errorf("rule %s exceeds its per-tenant quota", rule.Key)
	}

	if err := e.datapath.ApplyRule(ctx, rule); err != nil {
		// Reconcile only adds the key to e.active on success, so no later
		// removeRuleLocked would ever release the reservation made above.
		if relErr := e.quota.Release(ctx, rule.Key); relErr != nil {
			return errors.Join(
				fmt.Errorf("apply datapath rule %s: %w", rule.Key, err),
				fmt.Errorf("release quota for %s: %w", rule.Key, relErr),
			)
		}
		return fmt.Errorf("apply datapath rule %s: %w", rule.Key, err)
	}

	e.telemetry.RuleApplied(ctx, rule)
	return nil
}

// removeRuleLocked tears down a single rule's datapath and quota state.
// Caller must hold e.mu.
func (e *Engine) removeRuleLocked(ctx context.Context, key string) error {
	// Quota is released even when datapath removal fails, so a reservation
	// cannot outlive the rule. Release is a no-op for an already-released key,
	// so a retry stays correct.
	dpErr := e.datapath.RemoveRule(ctx, key)
	if dpErr != nil {
		dpErr = fmt.Errorf("remove datapath rule %s: %w", key, dpErr)
	}
	if err := e.quota.Release(ctx, key); err != nil {
		return errors.Join(dpErr, fmt.Errorf("release quota for %s: %w", key, err))
	}
	if dpErr != nil {
		return dpErr
	}

	e.telemetry.RuleRemoved(ctx, key)
	return nil
}
