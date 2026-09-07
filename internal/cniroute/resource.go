// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniroute

import (
	"log/slog"

	"go.datum.net/galactic/internal/cni/route"
)

// resourceTracker tracks the routes cmdAdd created, for selective rollback.
// This plugin's ADD only ever creates termination routes, so route deletion is
// all it unwinds: the VRF and interface it runs alongside belong to the master
// plugin's own tracker.
type resourceTracker struct {
	vpc, vpcAttachment, dev string
	added                   []Termination
}

// cleanup deletes every route this tracker recorded as added. Errors are
// logged but never returned — the caller already has a failure.
func (rt *resourceTracker) cleanup() {
	slog.Info("Selective rollback: cleaning up routes created during failed ADD",
		"vpc", rt.vpc, "vpcAttachment", rt.vpcAttachment)

	for _, term := range rt.added {
		if err := route.Delete(rt.vpc, term.Network, term.Via, rt.dev); err != nil {
			slog.Error("Rollback: failed to delete route", "err", err,
				"network", term.Network, "via", term.Via, "dev", rt.dev)
		} else {
			slog.Debug("Rollback: deleted route", "network", term.Network, "via", term.Via, "dev", rt.dev)
		}
	}
}
