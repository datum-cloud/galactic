// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"errors"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/edge/maintenance"
)

// ReclaimVPC is RunGC's reclamation of one VPC's orphaned BGPVRFInstance and
// host VRF on nodeName, for the process that owns the VPC's write fence and
// calls it with the fence held, inside its own commit. It judges the VPC on
// the same evidence RunGC does: live or unknown BGPAdvertisements, sidecar
// EndpointSlices, edge attachments and links enslaved to the VRF. It deletes
// under the VRF lock, so a link enslaved since collection keeps both. It
// never takes the fence itself. BGPAdvertisements are left to RunGC.
func ReclaimVPC(ctx context.Context, k8s client.Client, namespace, nodeName, vpc string, edge EdgeUsers) (
	CleanupResult, error) {
	var result CleanupResult
	// Collection reads edge use once for the pass; each delete reads it
	// again, as maintenance.Guard does under the fence.
	held := &passEdgeUsers{EdgeUsers: heldFence{EdgeUsers: edge}}
	want := map[string]struct{}{}
	addVPC(want, vpc)

	orphans, err := CollectOrphanedCRDs(ctx, k8s, namespace, nodeName, held)
	if err != nil {
		return result, fmt.Errorf("collect orphaned BGPVRFInstances: %w", err)
	}
	var instances []OrphanedCRD
	for _, o := range orphans {
		if o.Kind == kindBGPVRFInstance && vpcInSet(want, vpcFromName(o.Name)) {
			instances = append(instances, o)
		}
	}
	r := RemoveOrphanedCRDs(ctx, k8s, instances, held)
	result.OrphanedCRDsRemoved, result.Errors = r.OrphanedCRDsRemoved, r.Errors

	names, err := CollectOrphanedVRFs(ctx, k8s, namespace, nodeName, held)
	if err != nil {
		return result, fmt.Errorf("collect orphaned VRFs: %w", err)
	}
	var vrfs []string
	for _, name := range names {
		if v, ok := vpcFromVRFName(name); ok && vpcInSet(want, v) {
			vrfs = append(vrfs, name)
		}
	}
	r = RemoveOrphanedVRFs(ctx, vrfs, held)
	result.OrphanedVRFsRemoved, result.Errors = r.OrphanedVRFsRemoved, result.Errors+r.Errors
	if result.Errors > 0 {
		return result, errors.New("reclaim VPC: some deletions failed")
	}
	return result, nil
}

// heldFence is an EdgeUsers for a caller that already holds the VPC's write
// fence: Reclaim checks edge use again and runs reclaim directly, since
// taking the fence again would deadlock on its lock.
type heldFence struct {
	EdgeUsers
}

// Reclaim runs reclaim unless an edge attachment uses vpc, when it returns an
// error wrapping maintenance.ErrInUse.
func (h heldFence) Reclaim(ctx context.Context, vpc string, reclaim func() error) error {
	vpcs, err := h.VPCs(ctx)
	if err != nil {
		return err
	}
	if vpcInSet(vpcs, vpc) {
		return fmt.Errorf("%w: VPC %s", maintenance.ErrInUse, vpc)
	}
	return reclaim()
}

// VPCFromVRFName returns the base62 VPC a Galactic host VRF's interface name
// carries, without zero padding, and whether name is one.
func VPCFromVRFName(name string) (string, bool) { return vpcFromVRFName(name) }
