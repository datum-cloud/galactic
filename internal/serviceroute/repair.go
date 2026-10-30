//go:build linux

// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"fmt"
	"sort"
)

// repairChangedEntries withdraws all changed references before installing any
// replacements. Shared kernel keys must lose every old owner first; otherwise
// a late release could delete a replacement written by an earlier owner.
// Unchanged owners keep their references and forwarding state throughout.
// On failure the caller closes the gate and retries a complete generation.
func (p *EBPFRouteProgrammer) repairChangedEntries(changed map[string][][]appliedEntry) error {
	keys := make([]string, 0, len(changed))
	for key := range changed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, entries := range p.appliedRefs[key] {
			for i := len(entries) - 1; i >= 0; i-- {
				if err := p.release(entries[i]); err != nil {
					return fmt.Errorf("withdraw changed service route %s: %w", key, err)
				}
			}
		}
	}
	for _, key := range keys {
		sets := make([][]appliedEntry, 0, len(changed[key]))
		for _, entries := range changed[key] {
			applied, err := p.acquireSet(entries)
			if err != nil {
				return fmt.Errorf("repair changed service route %s: %w", key, err)
			}
			sets = append(sets, applied)
		}
		p.appliedRefs[key] = sets
	}
	return nil
}
