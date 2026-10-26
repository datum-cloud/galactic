// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
)

// Engine is the in-process gateway engine on one gateway node: a
// mutex-protected map of currently active state, converged toward a desired
// state on each Reconcile. It holds no VRF state, this datapath having no VRF
// dependency.
type Engine struct {
	mu      sync.Mutex
	active  map[string]DesiredRule
	pending map[string]DesiredRule

	// dirty holds active keys whose last apply or removal failed. Their
	// datapath and quota state no longer match their active rule, so the
	// next Reconcile applies them even when the desired rule equals it.
	dirty map[string]struct{}

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
		pending:   make(map[string]DesiredRule),
		dirty:     make(map[string]struct{}),
		datapath:  datapath,
		quota:     quota,
		telemetry: telemetry,
	}
}

// Reconcile converges live state toward desired: every rule in desired that is
// new or differs from its active version is applied, and every rule still
// active but no longer in desired is torn down. The caller must already have
// withdrawn a rule's BGP route before it disappears from desired.
//
// A rule equal to its active version is skipped: no quota reservation, no
// datapath write, no telemetry. It still gets an applied status, so the result
// carries one status per desired rule. A partial previous failure still
// self-heals on the next call: a new rule only becomes active once applied, and
// an active rule whose update or removal failed is marked dirty and applied
// again whatever its desired state.
func (e *Engine) Reconcile(ctx context.Context, desired EngineState) (EngineStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	inventory := make(map[string]DesiredRule, len(e.active)+len(e.pending))
	for key, rule := range e.active {
		inventory[key] = rule
	}
	for key, rule := range e.pending {
		inventory[key] = rule
	}
	toApply, toRemove := diffRuleKeys(inventory, desired.Rules)
	for key := range e.dirty {
		if _, ok := desired.Rules[key]; ok && !slices.Contains(toApply, key) {
			toApply = append(toApply, key)
		}
	}
	slices.Sort(toApply)

	applying := make(map[string]struct{}, len(toApply))
	for _, key := range toApply {
		applying[key] = struct{}{}
	}
	statuses := make([]RuleStatus, 0, len(desired.Rules)+len(toRemove))
	for key := range desired.Rules {
		if _, ok := applying[key]; !ok {
			statuses = append(statuses, RuleStatus{Key: key, Applied: true})
		}
	}
	for _, key := range toRemove {
		if err := e.removeRuleLocked(ctx, key); err != nil {
			e.dirty[key] = struct{}{}
			statuses = append(statuses, RuleStatus{Key: key, Applied: true, Error: err.Error()})
			continue
		}
		delete(e.active, key)
		delete(e.dirty, key)
	}
	for _, key := range toApply {
		rule := desired.Rules[key]
		blocked := false
		for _, removed := range toRemove {
			if old, exists := e.active[removed]; exists && rulesOverlap(old, rule) {
				blocked = true
			}
		}
		for oldKey, old := range e.pending {
			if oldKey != key && rulesOverlap(old, rule) {
				blocked = true
			}
		}
		if blocked {
			statuses = append(statuses, RuleStatus{Key: key, Error: "conflicting prior rule has not withdrawn"})
			continue
		}
		if _, pending := e.pending[key]; pending {
			if err := e.removeRuleLocked(ctx, key); err != nil {
				statuses = append(statuses, RuleStatus{Key: key, Error: err.Error()})
				continue
			}
		}
		if err := e.applyRuleLocked(ctx, rule); err != nil {
			// Failed writes are rolled back or retained as pending cleanup.
			// Either way an active rule must be rechecked before reporting success.
			if _, ok := e.active[key]; ok {
				e.dirty[key] = struct{}{}
			}
			if _, ok := e.pending[key]; ok {
				e.dirty[key] = struct{}{}
			}
			statuses = append(statuses, RuleStatus{Key: key, Applied: false, Error: err.Error()})
			continue
		}
		e.active[key] = rule
		delete(e.dirty, key)
		statuses = append(statuses, RuleStatus{Key: key, Applied: true})
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
	keys := make(map[string]struct{}, len(e.active)+len(e.pending))
	for key := range e.active {
		keys[key] = struct{}{}
	}
	for key := range e.pending {
		keys[key] = struct{}{}
	}
	for key := range keys {
		// A key whose teardown failed stays active whether or not an
		// earlier key already failed; only the first error is returned.
		if err := e.removeRuleLocked(ctx, key); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("stop: remove rule %s: %w", key, err)
			}
			e.dirty[key] = struct{}{}
			continue
		}
		delete(e.active, key)
		delete(e.dirty, key)
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

	e.pending[rule.Key] = rule
	if err := e.datapath.ApplyRule(ctx, rule); err != nil {
		// A failed write may have installed some rows. Retain inventory and quota
		// until rollback really succeeds, so another listener cannot reuse them.
		cleanupErr := e.datapath.RemoveRule(ctx, rule.Key)
		if cleanupErr != nil {
			return errors.Join(fmt.Errorf("apply datapath rule %s: %w",
				rule.Key,
				err),
				fmt.Errorf("rollback rule %s: %w",
					rule.Key,
					cleanupErr))
		}
		delete(e.pending, rule.Key)
		return errors.Join(fmt.Errorf("apply datapath rule %s: %w", rule.Key, err), e.quota.Release(ctx, rule.Key))
	}
	delete(e.pending, rule.Key)

	e.telemetry.RuleApplied(ctx, rule)
	return nil
}

// removeRuleLocked tears down a single rule's datapath and quota state.
// Caller must hold e.mu.
func (e *Engine) removeRuleLocked(ctx context.Context, key string) error {
	if err := e.datapath.RemoveRule(ctx, key); err != nil {
		return fmt.Errorf("remove datapath rule %s: %w", key, err)
	}
	if err := e.quota.Release(ctx, key); err != nil {
		return fmt.Errorf("release quota for %s: %w", key, err)
	}
	delete(e.pending, key)

	e.telemetry.RuleRemoved(ctx, key)
	return nil
}

func (e *Engine) SetOwnedVIPs(ctx context.Context, addrs []netip.Addr) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	guard, ok := e.datapath.(interface {
		SetOwnedVIPs(context.Context, []netip.Addr) error
	})
	if !ok {
		if len(addrs) == 0 {
			return nil
		}
		return errors.New("datapath does not support owned VIP protection")
	}
	return guard.SetOwnedVIPs(ctx, addrs)
}

func (e *Engine) SupportsPortRanges() bool {
	capability, ok := e.datapath.(interface{ SupportsPortRanges() bool })
	return ok && capability.SupportsPortRanges()
}

func rulesOverlap(a, b DesiredRule) bool {
	if a.Protocol != b.Protocol || a.Port > portEnd(b) || b.Port > portEnd(a) {
		return false
	}
	for _, addr := range a.VIPAddresses {
		if slices.Contains(b.VIPAddresses, addr) {
			return true
		}
	}
	return false
}
func (e *Engine) SupportsOwnedVIPs() bool {
	if capability, ok := e.datapath.(interface{ SupportsOwnedVIPs() bool }); ok {
		return capability.SupportsOwnedVIPs()
	}
	_, ok := e.datapath.(interface {
		SetOwnedVIPs(context.Context, []netip.Addr) error
	})
	return ok
}

// SetBlockedVIPs suppresses owned-address traffic while controller state converges.
func (e *Engine) SetBlockedVIPs(ctx context.Context, addrs []netip.Addr) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	guard, ok := e.datapath.(interface {
		SetBlockedVIPs(context.Context, []netip.Addr) error
	})
	if !ok {
		if len(addrs) == 0 {
			return nil
		}
		return errors.New("datapath does not support owned VIP blocking")
	}
	return guard.SetBlockedVIPs(ctx, addrs)
}
