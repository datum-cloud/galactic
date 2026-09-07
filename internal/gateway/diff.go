// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import "sort"

// diffRuleKeys compares the currently active rule keys against the desired state
// and returns which need applying and which removing.
//
// A key present in both is always returned in toApply: the engine applies
// unconditionally rather than diffing individual field changes. The two slices
// partition the key space, not changed against unchanged.
//
// Both are sorted, for deterministic log output and test assertions, the inputs
// being maps whose iteration order is randomized.
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
