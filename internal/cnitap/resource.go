// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"log/slog"

	"github.com/containernetworking/plugins/pkg/ipam"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/plumbing/dan"
)

// resourceTracker tracks the resources cmdAdd created, for selective rollback.
// This plugin's ADD only ever creates the VRF, the tap device, and, when
// delegated, an IPAM allocation. BGP publishing and termination routes are
// separate chain-invoked plugins with their own trackers.
type resourceTracker struct {
	vpc, vpcAttachment string

	// ipamDelegated, ipamType, and ipamStdin record enough to release the IPAM
	// allocation during rollback. They are set on the ipam block's presence
	// alone, not only after a confirmed delegated add; see the veth plugin's
	// tracker for the full reasoning.
	ipamDelegated bool
	ipamType      string
	ipamStdin     []byte

	// danDir and danSandboxID locate the DAN file to unlink during rollback.
	// They are empty for an attachment that did not ask for one, and cleanup
	// tolerates a file that was never written.
	danDir, danSandboxID string
}

// cleanup rolls back the tracked resources in reverse creation order.
//
// Deliberately absent: deleting the VRF. Removing this attachment's tap device
// is safe, that device being private to it, but the VRF is shared by every
// attachment on this VPC on this node, and creating it is idempotent, so a flag
// here could never tell "I created it" from "a sibling already had". Deleting it
// on a failed ADD could tear down a live sibling's VRF. Reclaiming it is garbage
// collection's job.
func (rt *resourceTracker) cleanup() {
	// Release the IPAM allocation first, whenever an ipam block was configured
	// at all. Interface and VRF cleanup is shared with the veth plugin's
	// tracker, so it lives in the shared master-plugin package.
	if rt.ipamDelegated {
		if err := ipam.ExecDel(rt.ipamType, rt.ipamStdin); err != nil {
			slog.Error("Rollback: failed to release IPAM allocation", "err", err, "ipamType", rt.ipamType)
		} else {
			slog.Debug("Rollback: released IPAM allocation", "ipamType", rt.ipamType)
		}
	}

	// Unlink the DAN file before the tap it names goes away, so no window
	// exists where a shim could adopt a device that is being deleted.
	if rt.danDir != "" && rt.danSandboxID != "" {
		if err := dan.Remove(rt.danDir, rt.danSandboxID); err != nil {
			slog.Error("Rollback: failed to remove DAN file", "err", err, "dir", rt.danDir)
		}
	}

	cnimaster.CleanupAttachment(rt.vpc, rt.vpcAttachment, "tap", tap.Delete)
}
