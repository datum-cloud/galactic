// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"slices"
	"sort"
)

// diffRuleKeys compares the currently active rule keys against the desired state
// and returns which need applying and which removing.
//
// A key is in toApply when it is not active yet or its desired rule differs from
// the active one. An unchanged rule is left out, so an event that changes nothing
// a rule depends on, such as a pod attach elsewhere in the namespace, writes
// nothing to the datapath.
//
// Both are sorted, for deterministic log output and test assertions, the inputs
// being maps whose iteration order is randomized.
func diffRuleKeys(active map[string]DesiredRule, desired map[string]DesiredRule) (toApply, toRemove []string) {
	for key, rule := range desired {
		if cur, ok := active[key]; ok && rulesEqual(cur, rule) {
			continue
		}
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

// rulesEqual reports whether a and b would program identical datapath state.
// VIPAddresses and Backends compare in order: the controller builds both in
// spec order, so a reordered spec reapplies once with the same result.
func rulesEqual(a, b DesiredRule) bool {
	return a.Key == b.Key &&
		a.VPCRef == b.VPCRef &&
		a.Protocol == b.Protocol &&
		a.Port == b.Port &&
		slices.Equal(a.VIPAddresses, b.VIPAddresses) &&
		slices.Equal(a.Backends, b.Backends)
}
