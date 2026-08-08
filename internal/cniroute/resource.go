// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniroute

import (
	"log/slog"

	"go.datum.net/galactic/internal/cni/route"
)

// resourceTracker tracks routes created during cmdAdd for selective
// rollback. galactic-route's own ADD only ever creates termination
// routes — route-delete only, per the plan's decision that each binary's
// tracker unwinds exactly what its own ADD created (the VRF/veth-or-tap
// it runs alongside belongs to the master plugin's own tracker instead).
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
		if err := route.Delete(rt.vpc, rt.vpcAttachment, term.Network, term.Via, rt.dev); err != nil {
			slog.Error("Rollback: failed to delete route", "err", err,
				"network", term.Network, "via", term.Via, "dev", rt.dev)
		} else {
			slog.Debug("Rollback: deleted route", "network", term.Network, "via", term.Via, "dev", rt.dev)
		}
	}
}
