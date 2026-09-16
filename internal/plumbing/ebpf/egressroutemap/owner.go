// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"fmt"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// SidecarOwnedTableIDs returns the Linux VRF routing table IDs whose
// egress_route_table entries were written from inside an ingress sidecar's own
// pod network namespace.
//
// The sidecar mounts the host's bpffs, so it registers into the same pinned
// maps the host CNI installer does. It does not share the host's network
// namespace, and every encapsulating entry carries a link index and a pair of
// L2 addresses resolved in whichever namespace wrote it. A host-resolved link
// index does not exist inside the pod, and a pod-resolved one does not exist on
// the host, so neither writer may re-resolve the other's entries.
//
// Nothing in egress_route_table's own key or value records who wrote an entry,
// and its key carries only a routing table ID, which each namespace allocates
// from 1 upward independently. vrf_table does record it: the sidecar registers
// every VRF it serves under uformat.BlockIngressSidecar, a Block no CNI
// attachment can reach, and does so before installing any route into that
// table. Reading those rows back is therefore enough to tell the two
// populations apart without a second copy of the ownership state.
func SidecarOwnedTableIDs(vrfTable *usidmap.VRFTable) (map[uint32]struct{}, error) {
	entries, err := vrfTable.List()
	if err != nil {
		return nil, fmt.Errorf("egressroutemap: resolve ingress-sidecar-owned VRF tables: %w", err)
	}
	owned := make(map[uint32]struct{})
	for _, entry := range entries {
		if entry.Block == uformat.BlockIngressSidecar {
			owned[entry.VRFTableID] = struct{}{}
		}
	}
	return owned, nil
}
