// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"log/slog"
	"os"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/mssclamp"
)

// mssClampState keeps the datapath's TCP MSS clamp in step with the uplink
// MTU. It is reconciled once when the datapath loads and again on every eBPF
// health tick, so an uplink whose MTU changes is followed within one tick and
// a value lost to a recreated map is restored.
type mssClampState struct {
	reconciler *mssclamp.Reconciler
	lastErr    string
}

// newMSSClampState returns the clamp's state for table, read from the
// GALACTIC_CNI_TCP_MSS_CLAMP setting and sized from the interfaces the uSID
// datapath attaches to.
func newMSSClampState(table mssclamp.Putter) *mssClampState {
	override := os.Getenv(config.EnvCNITCPMSSClamp)
	return &mssClampState{reconciler: mssclamp.NewReconciler(table, override, attach.ResolveInterfaces)}
}

// reconcile writes the clamp if it changed, logging a change once and a
// failure once per distinct error rather than on every tick.
//
// A failure leaves the map as it was. On a node that never resolved its
// uplink MTU that is zero, clamping off, so the datapath behaves as it did
// before the clamp existed; full-size TCP segments across the fabric are then
// dropped, as they were before, until the MTU resolves.
func (s *mssClampState) reconcile() {
	if s == nil {
		return
	}
	v, changed, err := s.reconciler.Reconcile()
	if err != nil {
		if msg := err.Error(); msg != s.lastErr {
			slog.Warn("TCP MSS clamp not updated; the datapath keeps its previous values",
				"setting", config.EnvCNITCPMSSClamp, "err", err)
			s.lastErr = msg
		}
		return
	}
	s.lastErr = ""
	if !changed {
		return
	}
	if v.IsOff() {
		slog.Info("TCP MSS clamp disabled", "setting", config.EnvCNITCPMSSClamp)
		return
	}
	slog.Info("TCP MSS clamp set", "ipv4", v.IPv4, "ipv6", v.IPv6)
}
