// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"fmt"
)

// ReconcileOrphans identifies and cleans up vip_table state left behind
// by a gateway engine process that crashed mid-reconcile.
//
// Unlike an earlier, rejected design's identically-named method
// (which scanned live Geneve interfaces against a desired VNI set), this
// design has no kernel interface state of its own to leak — the only
// thing a crashed process can leave behind is a vip_table row with no
// corresponding NetworkRule left to reconcile it against. That is exactly
// what internal/plumbing/ebpf/edgemap.VIPTable.Reconcile's own
// Generation-cutoff mechanism already handles, so this method is a thin,
// correctly-ordered wrapper around Datapath.ReconcileOrphans rather than a
// second, independent orphan-detection mechanism.
//
// cutoff must have been captured via Engine.DatapathGeneration *before*
// desired's NetworkRule CRDs were listed — an entry written after that
// snapshot but before this call runs is a legitimate fresh Register this
// method must not race, not an orphan (see
// internal/plumbing/ebpf/edgemap's VIPTable.Generation doc comment for
// the same ordering contract at the map layer).
//
// Unlike Reconcile, ReconcileOrphans does not rely on Engine's in-memory
// active map — that map is empty immediately after a crash/restart, which
// is exactly the situation this method exists to recover from.
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
