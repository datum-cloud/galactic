// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"log/slog"
	"time"

	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

// datapathRepairRetryInterval is the first wait between startup repair passes
// that need repeating. Each later wait doubles, up to
// datapathRepairMaxRetryInterval. datapathRepairPendingLimit bounds how long
// the startup passes keep repeating for attachments whose BGPRouter or
// BGPVRFInstance is not found yet; after it the GC tick takes over. Vars so
// tests can shrink them.
var (
	datapathRepairRetryInterval    = 15 * time.Second
	datapathRepairMaxRetryInterval = 5 * time.Minute
	datapathRepairPendingLimit     = 10 * time.Minute
)

// repairDatapathFn is gc.RepairAttachmentDatapath, indirected so tests can
// observe passes without a datapath or an API server.
var repairDatapathFn = gc.RepairAttachmentDatapath

// datapathRepairEnabled reports whether st has a loaded datapath and a
// Kubernetes client, without which there is nothing to repair or nothing to
// repair it from.
func datapathRepairEnabled(st ebpfDatapathState) bool {
	return st.objs != nil && st.k8sClient != nil
}

// isSidecarReturnTable reports whether tableID is one of the routing tables
// the sidecar return path allocates. The datapath repair must never treat one
// as an attachment's VRF, and this range check is what stops it: the
// sidecar's own vrf_table rows, which also mark such tables, may be among the
// rows a recreated map has lost.
func isSidecarReturnTable(tableID uint32) bool {
	return tableID >= sidecarReturnTableBase && tableID <= sidecarReturnTableMax
}

// runDatapathRepair runs one gc.RepairAttachmentDatapath pass and logs one
// summary line with the rows it rebuilt per map: at Info when it rebuilt
// anything, at Warn when it failed or left the public uplink unresolved, and
// at Debug otherwise. It returns the pass's result and error.
func runDatapathRepair(ctx context.Context, st ebpfDatapathState) (gc.DatapathRepairResult, error) {
	result, err := repairDatapathFn(ctx, st.k8sClient, gc.DatapathRepairConfig{
		Namespace:      st.namespace,
		NodeName:       st.nodeName,
		PinDir:         attach.PinDir,
		Egress:         st.egress,
		ForeignTableID: isSidecarReturnTable,
	})

	attrs := append([]any{"attachments", result.Attachments, "skipped", result.Skipped,
		"pending", result.Pending, "rebuilt", result.Rebuilt.Total()}, result.Rebuilt.LogAttrs()...)
	switch {
	case err != nil:
		slog.Warn("eBPF attachment datapath repair failed; rows CNI ADD wrote may still be missing",
			append(attrs, "err", err)...)
	case result.UplinkErr != nil:
		slog.Warn("eBPF attachment datapath repair could not rebuild this node's public uplink",
			append(attrs, "uplinkErr", result.UplinkErr)...)
	case result.Rebuilt.Total() > 0:
		slog.Info("eBPF attachment datapath repair rebuilt missing rows", attrs...)
	default:
		slog.Debug("eBPF attachment datapath repair found nothing missing", attrs...)
	}
	return result, err
}

// startDatapathRepair runs datapath repair passes off Run's goroutine,
// waiting datapathRepairRetryInterval before the first repeat and doubling
// each wait after that. A pass that fails is repeated until one succeeds. A
// pass that leaves attachments pending is repeated until none are or
// datapathRepairPendingLimit has passed since the first. ctx ending stops it.
//
// sem is the size-1 semaphore the GC tick's pass shares, held only for the
// length of a pass, so the two never run at once.
func startDatapathRepair(ctx context.Context, sem chan struct{}, st ebpfDatapathState) {
	if !datapathRepairEnabled(st) {
		return
	}
	wait, maxWait, pendingLimit := datapathRepairRetryInterval, datapathRepairMaxRetryInterval, datapathRepairPendingLimit
	go func() {
		started := time.Now()
		for {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			result, err := runDatapathRepair(ctx, st)
			<-sem
			pending := result.Pending > 0 && time.Since(started) < pendingLimit
			if err == nil && !pending {
				return
			}

			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
			wait = min(wait*2, maxWait)
		}
	}()
}

// repairDatapathOnTick starts one datapath repair pass off Run's goroutine,
// unless a pass already holds sem, in which case that pass covers this tick.
// A pass can wait on neighbor resolution, so running it on Run's goroutine
// would stall every other ticker and shutdown.
func repairDatapathOnTick(ctx context.Context, sem chan struct{}, st ebpfDatapathState) {
	if !datapathRepairEnabled(st) {
		return
	}
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() { <-sem }()
			_, _ = runDatapathRepair(ctx, st)
		}()
	default:
	}
}
