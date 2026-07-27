// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"context"
	"log/slog"
	"time"
)

// RunPatchLoop periodically re-applies PatchConflistDir until ctx is
// canceled. Running as a loop rather than a one-shot init container is a
// deliberate hedge against two ordering problems neither Kubernetes nor
// this plugin can otherwise guarantee: Cilium's own DaemonSet may not have
// written its conflist yet the first time this container starts, and
// Cilium can rewrite its conflist later (e.g. on an upgrade), which would
// silently drop vmtap-cni back out of the chain until the next patch.
//
// It is still not a complete answer to the conflist-chaining problem in
// .local/kraftlet-cilium-tap-plan.md section 7 — in particular, nothing
// here guarantees this patch lands before Cilium's own CNI starts
// servicing ADD calls on a freshly booted node, only that it eventually
// converges.
func RunPatchLoop(ctx context.Context, dir, glob string, interval time.Duration) {
	patchOnce := func() {
		patched, err := PatchConflistDir(dir, glob)
		if err != nil {
			slog.Error("conflist patch: failed", "dir", dir, "glob", glob, "err", err)
			return
		}
		for _, path := range patched {
			slog.Info("conflist patch: appended vmtap-cni to plugin chain", "path", path)
		}
	}

	patchOnce()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			patchOnce()
		}
	}
}
