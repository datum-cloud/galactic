// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"net/netip"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// LocalTable is edge_local_table as internal/gateway/localhandoff writes it:
// for each backend on this node, keyed by the uSID edge_lb selects, the TAP
// its flows are handed to through Galactic Worker's Local handoff, or none,
// which makes edge_lb drop them. A backend with no row is encapsulated.
// galactic-gateway owns every row.
type LocalTable struct {
	t *edgemap.LocalTable
}

// NewLocalTable wraps the loaded program's edge_local_table.
func NewLocalTable(objs *edgeprog.EdgedsrObjects) *LocalTable {
	return &LocalTable{t: edgemap.NewLocalTable(edgemap.KernelTable{Map: objs.EdgeLocalTable})}
}

// Set writes sid's row. tapIfindex 0 drops the backend's flows.
func (l *LocalTable) Set(sid netip.Addr, tapIfindex uint32) error {
	return l.t.SetLocalBackend(sid, tapIfindex, l.t.Generation())
}

// Delete removes sid's row; a missing row is not an error.
func (l *LocalTable) Delete(sid netip.Addr) error { return l.t.DeleteLocalBackend(sid) }

// List returns every row's TAP.
func (l *LocalTable) List() (map[netip.Addr]uint32, error) { return l.t.LocalBackends() }
