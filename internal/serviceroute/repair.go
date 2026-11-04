//go:build linux

// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"fmt"
	"reflect"
	"sort"
)

// repairChangedEntries moves changed intents to their fresh entries. An entry
// present before and after keeps its references and kernel state, so a
// consumer's route stays up while one producer's interface is recreated.
//
// Changed references are withdrawn before any replacement is installed.
// Shared kernel keys must lose every old owner first; otherwise a late release
// could delete a replacement written by an earlier owner. Producer sets are
// the exception: their refs stack under the route's key, so a new set goes in
// before the old one comes out and the route always has one.
// Unchanged owners keep their references and forwarding state throughout.
// On failure the caller closes the gate and retries a complete generation.
func (p *EBPFRouteProgrammer) repairChangedEntries(changed map[string][][]appliedEntry) error {
	keys := make([]string, 0, len(changed))
	for key := range changed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	stale := make(map[string][][]appliedEntry, len(keys))
	added := make(map[string][][]appliedEntry, len(keys))
	for _, key := range keys {
		for i, entries := range p.appliedRefs[key] {
			oldOnly, newOnly := diffEntries(entries, changed[key][i])
			stale[key] = append(stale[key], oldOnly)
			added[key] = append(added[key], newOnly)
		}
	}
	withdraw := func(sets bool) error {
		for _, key := range keys {
			for _, entries := range stale[key] {
				for i := len(entries) - 1; i >= 0; i-- {
					if (entries[i].set != nil) != sets {
						continue
					}
					if err := p.release(entries[i]); err != nil {
						return fmt.Errorf("withdraw changed service route %s: %w", key, err)
					}
				}
			}
		}
		return nil
	}
	if err := withdraw(false); err != nil {
		return err
	}
	for _, key := range keys {
		for _, entries := range added[key] {
			if _, err := p.acquireSet(entries); err != nil {
				return fmt.Errorf("repair changed service route %s: %w", key, err)
			}
		}
	}
	if err := withdraw(true); err != nil {
		return err
	}
	for _, key := range keys {
		p.appliedRefs[key] = changed[key]
	}
	return nil
}

// diffEntries returns the entries of before that after lacks, and those of
// after that before lacks, each in its own order. Equal entries pair up one to
// one.
func diffEntries(before, after []appliedEntry) (oldOnly, newOnly []appliedEntry) {
	matched := make([]bool, len(before))
	for _, entry := range after {
		found := false
		for i, old := range before {
			if !matched[i] && reflect.DeepEqual(old, entry) {
				matched[i], found = true, true
				break
			}
		}
		if !found {
			newOnly = append(newOnly, entry)
		}
	}
	for i, old := range before {
		if !matched[i] {
			oldOnly = append(oldOnly, old)
		}
	}
	return oldOnly, newOnly
}
