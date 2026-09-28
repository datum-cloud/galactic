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
	"go.datum.net/galactic/internal/plumbing/radv"
)

// resourceTracker tracks the resources cmdAdd created, for selective rollback.
// This plugin's ADD only ever creates the VRF, the tap device, and, when
// delegated, an IPAM allocation. BGP publishing and termination routes are
// separate chain-invoked plugins with their own trackers.
type resourceTracker struct {
	vpc, vpcAttachment string

	// containerID is the CNI container ID this ADD is running for, and so the
	// owner stamped on any tap it created or adopted. Rollback passes it to
	// tap.Delete so a failed ADD that lost the attachment to a concurrent one
	// tears down nothing of the winner's.
	containerID string

	// tapAdopted and tapPriorOwner record how this ADD's tap step resolved:
	// whether it created this attachment's tap or took over one that already
	// existed, and, if so, who owned it before. Rollback branches on them,
	// mirroring the veth plugin's tracker: a tap this ADD created is ours to
	// remove; one it took over from a still-terminating predecessor must be
	// handed back to that owner instead, or a failed ADD would tear down a
	// live container's interface.
	tapAdopted    bool
	tapPriorOwner string

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

	// radvHostInterface names the Router Advertisement record ADD wrote, empty
	// until it is written. The record names the tap, so it must go with it: one
	// left behind has the node daemon waiting on an interface that is gone.
	radvHostInterface string
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

	// Remove the Router Advertisement record before the tap it names, matching
	// DEL's order.
	if rt.radvHostInterface != "" {
		if err := radv.RemoveAttachment(radv.DefaultStateDir, rt.radvHostInterface); err != nil {
			slog.Error("Rollback: failed to remove router advertisement record", "err", err,
				"name", rt.radvHostInterface)
		}
	}

	cnimaster.CleanupAttachment(rt.vpc, rt.vpcAttachment, "tap", func(vpc, vpcAttachment string) error {
		// A tap this ADD created is ours to delete; one it adopted from a
		// still-terminating predecessor must be handed back to that owner so
		// a failed ADD does not remove a live container's interface. An
		// adopted tap with no prior owner (unowned debris) has no one to
		// reclaim it, so it is deleted like one we created.
		if rt.tapAdopted && rt.tapPriorOwner != "" {
			return tap.RestoreOwner(vpc, vpcAttachment, rt.tapPriorOwner)
		}
		return tap.Delete(vpc, vpcAttachment, rt.containerID)
	})
}
