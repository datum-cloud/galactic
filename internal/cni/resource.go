// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"log/slog"

	"github.com/containernetworking/plugins/pkg/ipam"

	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/cnimaster"
)

// resourceTracker tracks the resources cmdAdd created, for selective rollback.
// This plugin's ADD only ever creates the VRF, the veth pair, and, when
// delegated, an IPAM allocation. BGP publishing and termination routes are
// separate chain-invoked plugins with their own trackers.
type resourceTracker struct {
	vpc, vpcAttachment string

	// ipamDelegated, ipamType, and ipamStdin record enough to release the IPAM
	// allocation during rollback.
	//
	// They are set as soon as an ipam block is known to be present, before the
	// delegated add is even attempted, rather than only after it succeeds. The
	// delegated delete is idempotent per the protocol, doing nothing when it
	// finds no allocation, so calling it whenever a block was configured is safe
	// and covers every failure path including ones where the add never ran.
	// Without that, a failed ADD past the IPAM step permanently burns an address
	// out of the pool, the on-disk marker having no implicit teardown.
	ipamDelegated bool
	ipamType      string
	ipamStdin     []byte
}

// cleanup rolls back every tracked resource in reverse creation order. Errors
// are logged and never returned, the caller already having a failure. It takes
// no context: the only non-kernel call left is the delegated IPAM delete, which
// shells out to a binary rather than making an API call.
//
// Deliberately absent: deleting the VRF. Removing this attachment's veth pair is
// safe, that pair being private to it, but the VRF is shared by every
// attachment on this VPC on this node, and creating it is idempotent, so there
// is no way to tell "I created it" from "a sibling already had". Deleting it on
// a failed ADD could tear down a live sibling's VRF. Reclaiming it is garbage
// collection's job, once it has confirmed no advertisement for this VPC and
// node remains.
func (rt *resourceTracker) cleanup() {
	// Release the IPAM allocation first, whenever an ipam block was configured
	// at all. Interface and VRF cleanup is shared with the tap plugin's tracker,
	// so it lives in the shared master-plugin package.
	if rt.ipamDelegated {
		if err := ipam.ExecDel(rt.ipamType, rt.ipamStdin); err != nil {
			slog.Error("Rollback: failed to release IPAM allocation", "err", err, "ipamType", rt.ipamType)
		} else {
			slog.Debug("Rollback: released IPAM allocation", "ipamType", rt.ipamType)
		}
	}

	cnimaster.CleanupAttachment(rt.vpc, rt.vpcAttachment, "veth", veth.Delete)
}
