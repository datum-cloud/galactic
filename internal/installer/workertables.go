// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"errors"
	"fmt"
	"os"

	"go.datum.net/galactic/internal/cni/vpcfence"
	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// workerTenantTablesFn returns the VRF tables whose tenant routes a
// galactic-worker incarnation writes. A package var so tests can state them
// without a host VRF or a fence directory.
var workerTenantTablesFn = workerTenantTables

// workerTenantTables returns the table of every host VRF whose VPC scope a
// galactic-worker incarnation owns. Worker's Fabric module writes those
// VRFs' tenant routes and keeps their next hops current. A node with no fence
// directory has no Worker, and none.
func workerTenantTables() (map[uint32]struct{}, error) {
	auth, err := ownership.Open(vpcfence.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open VPC write fence: %w", err)
	}
	links, err := vrf.ListVRFLinks()
	if err != nil {
		return nil, fmt.Errorf("list VRF links: %w", err)
	}
	tables := map[uint32]struct{}{}
	for _, l := range links {
		vpc, ok := gc.VPCFromVRFName(l.Name)
		if !ok {
			continue
		}
		rec, err := auth.Read(ownership.VPCScope(vpc))
		if err != nil {
			return nil, fmt.Errorf("read VPC %s write fence: %w", vpc, err)
		}
		if ownership.WorkerOwned(rec.Owner) {
			tables[l.Table] = struct{}{}
		}
	}
	return tables, nil
}
