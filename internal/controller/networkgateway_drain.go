// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"sync"
	"time"

	"go.datum.net/galactic/internal/gateway"
)

// ruleDrainDelay is how long a gateway node keeps serving a deleted
// NetworkRule after the last of its BGPAdvertisements is gone. Deleting the
// object only starts the withdrawal: each router still has to send it and
// every peer has to act on it. Until then traffic keeps arriving for the VIP,
// and a node that already dropped the rule from its datapath would blackhole
// it.
const ruleDrainDelay = 5 * time.Second

// ruleDrainTracker remembers what this node put in the engine's desired state
// on its last pass, so a rule that is deleted can stay loaded for
// ruleDrainDelay after its advertisements are gone, even once the NetworkRule
// object itself has disappeared from the list.
//
// It holds memory only. After a process restart it knows nothing, and a
// deleted rule leaves the datapath on the first pass, as it did before the
// drain existed.
type ruleDrainTracker struct {
	mu sync.Mutex

	// last maps each rule key in the previous pass's desired state to the rule
	// as loaded.
	last map[string]drainEntry

	// holdUntil maps the key of each deleted rule whose advertisements are gone
	// to the time this node may drop it from the datapath.
	holdUntil map[string]time.Time
}

// drainEntry is one rule as the tracker remembers it.
type drainEntry struct {
	namespace string
	rule      gateway.DesiredRule
}

// lastLoaded returns the rule as this node last put it in desired state, for a
// draining rule that no longer builds, such as one whose backends were deleted
// alongside it.
func (t *ruleDrainTracker) lastLoaded(key string) (gateway.DesiredRule, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.last[key]
	return e.rule, ok
}

// settle completes desired for one pass in namespace and records it for the
// next. live holds the key of every listed NetworkRule that is not being
// deleted.
//
// A rule in last that is in neither desired nor live was deleted and its
// advertisements are gone. It goes back into desired until ruleDrainDelay has
// passed since this node first saw it that way. A rule in live but missing
// from desired, one that stopped building or lost Accepted, is dropped
// straight away: its own outcome already withdrew this node's advertisements.
//
// settle returns how long until the earliest hold ends, or zero when nothing
// is held.
func (t *ruleDrainTracker) settle(
	now time.Time, namespace string, desired map[string]gateway.DesiredRule, live map[string]bool,
) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.holdUntil == nil {
		t.holdUntil = make(map[string]time.Time)
	}

	var requeue time.Duration
	for key, e := range t.last {
		if e.namespace != namespace {
			continue
		}
		if _, ok := desired[key]; ok || live[key] {
			continue
		}
		until, held := t.holdUntil[key]
		if !held {
			until = now.Add(ruleDrainDelay)
			t.holdUntil[key] = until
		}
		if !now.Before(until) {
			delete(t.holdUntil, key)
			continue
		}
		desired[key] = e.rule
		if remaining := until.Sub(now); requeue == 0 || remaining < requeue {
			requeue = remaining
		}
	}

	next := make(map[string]drainEntry, len(desired))
	for key, e := range t.last {
		if e.namespace != namespace {
			next[key] = e
		}
	}
	for key, rule := range desired {
		next[key] = drainEntry{namespace: namespace, rule: rule}
	}
	for key := range t.holdUntil {
		// A rule recreated under the same name while its predecessor was held
		// is served, or withdrawn, as the new rule, with no hold left over.
		if _, ok := next[key]; !ok || live[key] {
			delete(t.holdUntil, key)
		}
	}
	t.last = next
	return requeue
}

// reset forgets everything, for when the engine is stopped and nothing is
// loaded.
func (t *ruleDrainTracker) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.last = nil
	t.holdUntil = nil
}
