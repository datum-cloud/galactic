// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"fmt"
)

// ReconcileOrphans cleans up vip_table state left behind by a gateway engine
// process that crashed mid-reconcile.
//
// This design has no kernel interface state of its own to leak: the only thing a
// crashed process can leave behind is a map row with no rule left to reconcile
// it against, which the map layer's generation cutoff already handles. So this
// is a correctly ordered wrapper around the datapath's own orphan sweep rather
// than a second detection mechanism.
//
// cutoff must have been read before desired's CRDs were listed. An entry written
// after that snapshot but before this call is a legitimate fresh registration
// this must not race, not an orphan.
//
// Unlike Reconcile, it does not rely on the engine's in-memory active map: that
// map is empty immediately after a restart, which is exactly the situation this
// exists to recover from.
func (e *Engine) ReconcileOrphans(ctx context.Context, desired EngineState, cutoff uint64) error {
	live := make([]DesiredRule, 0, len(desired.Rules))
	for _, rule := range desired.Rules {
		live = append(live, rule)
	}

	if err := e.datapath.ReconcileOrphans(ctx, live, cutoff); err != nil {
		return fmt.Errorf("reconcile orphaned datapath state: %w", err)
	}
	return nil
}
