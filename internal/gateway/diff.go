// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import "sort"

// diffRuleKeys compares the currently-active rule keys against the desired
// EngineState and returns which keys need to be (re)applied and which need
// to be removed. A key present in both sets is always returned in toApply
// (Engine.Reconcile applies unconditionally rather than trying to diff
// individual field changes — matching GoBGPRuntime's own "re-apply the
// whole desired set" convergence style) — toApply/toRemove partition the
// *key space*, not "changed vs. unchanged".
//
// Both returned slices are sorted for deterministic iteration order (log
// output, test assertions) — desired/active are Go maps, whose iteration
// order is intentionally randomized.
func diffRuleKeys(active map[string]DesiredRule, desired map[string]DesiredRule) (toApply, toRemove []string) {
	for key := range desired {
		toApply = append(toApply, key)
	}
	for key := range active {
		if _, ok := desired[key]; !ok {
			toRemove = append(toRemove, key)
		}
	}
	sort.Strings(toApply)
	sort.Strings(toRemove)
	return toApply, toRemove
}
