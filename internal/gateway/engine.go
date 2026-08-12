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

// Engine is the in-process gateway engine running on one gateway node,
// mirroring internal/runtime/gobgp's GoBGPRuntime shape: a mutex-protected
// map of currently-active state, converged towards a desired state on each
// Reconcile call.
//
// Unlike an earlier, rejected design's identically-named type,
// Engine holds no VRF/Geneve state at all — no vrfLinkNames map, no
// SetVRFLink method — because this datapath has no VRF dependency (see
// doc.go).
type Engine struct {
	mu     sync.Mutex
	active map[string]DesiredRule

	datapath  Datapath
	quota     QuotaEnforcer
	telemetry TelemetryEmitter
}

// NewEngine returns an Engine wired to the given Datapath, QuotaEnforcer,
// and TelemetryEmitter implementations. Production callers pass
// KernelDatapath (kerneldatapath.go), NoopQuotaEnforcer{}, and
// NoopTelemetryEmitter{} until those interfaces' real implementations
// land; tests pass fakes.
func NewEngine(datapath Datapath, quota QuotaEnforcer, telemetry TelemetryEmitter) *Engine {
	return &Engine{
		active:    make(map[string]DesiredRule),
		datapath:  datapath,
		quota:     quota,
		telemetry: telemetry,
	}
}

// Reconcile converges the engine's live state toward desired: every rule in
// desired.Rules is (re-)applied via Datapath.ApplyRule, and every rule no
// longer present in desired.Rules but still active is torn down via
// Datapath.RemoveRule (the caller must already have withdrawn its BGP
// route before it ever disappears from desired — see Datapath.RemoveRule's
// doc comment).
//
// Reconcile is intentionally "apply everything in desired, remove
// everything not in desired" rather than a fine-grained field-level diff —
// matching GoBGPRuntime.Apply's own convergence style — so a partial
// previous failure (e.g. the process crashed between two rules) always
// self-heals on the next call rather than requiring the caller to track
// what succeeded.
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

// Stop tears down every currently-active rule. The caller must already
// have withdrawn BGP routes for every rule before calling this, exactly as
// for an individual rule removal via Reconcile.
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

// DatapathGeneration returns a snapshot of the underlying Datapath's
// monotonic clock. Callers intending to call ReconcileOrphans must invoke
// this *before* listing the NetworkRule CRDs that will become that call's
// live set — see Datapath.Generation's doc comment for why the ordering
// matters, and recovery.go for the full crash-recovery contract.
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
	// cannot outlive the rule; Release is a no-op for an already-released
	// key, so the caller's next retry stays correct.
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
