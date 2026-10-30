// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"log/slog"

	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/ebpf/metrics"
)

// reenslaveHostLinksFn is hostgw.ReenslaveMasterlessHostLinks, indirected so
// tests can observe passes without touching the kernel.
var reenslaveHostLinksFn = hostgw.ReenslaveMasterlessHostLinks

// runHostLinkRepair runs one hostgw.ReenslaveMasterlessHostLinks pass and
// records it in m. The pass logs each link it re-enslaves or cannot; this
// adds a line only for a pass that failed.
func runHostLinkRepair(m *metrics.HostLinks) {
	result, err := reenslaveHostLinksFn()
	m.Pass(result.Reenslaved, result.Masterless)
	if err != nil {
		slog.Error("Host link repair failed; a host link may still have no VRF master",
			"reenslaved", result.Reenslaved, "masterless", result.Masterless, "err", err)
	}
}

// startHostLinkRepair runs one runHostLinkRepair pass off Run's goroutine,
// unless a pass already holds sem, in which case that pass covers this tick.
// The pass waits for the node's VRF lock, which a CNI ADD holds while it
// creates a host link, so running it on Run's goroutine could stall every
// other ticker.
func startHostLinkRepair(sem chan struct{}, m *metrics.HostLinks) {
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() { <-sem }()
			runHostLinkRepair(m)
		}()
	default:
	}
}
