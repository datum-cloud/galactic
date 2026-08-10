// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"log/slog"

	"github.com/containernetworking/plugins/pkg/ipam"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cnimaster"
)

// resourceTracker tracks resources created during cmdAdd for selective
// rollback. galactic-tap-cni's ADD only ever creates the VRF, the tap
// device, and (if delegated) an IPAM allocation — BGP/SRv6/eBPF publish is
// galactic-bgp's own, separately chain-invoked plugin now, with its own
// smaller tracker (internal/cnibgp); termination routes are galactic-
// route's own, with its own smaller tracker (internal/cniroute).
type resourceTracker struct {
	vpc, vpcAttachment string

	// ipamDelegated, ipamType, and ipamStdin record enough to release the
	// IPAM allocation during rollback — see internal/cni's own
	// resourceTracker for the full doc comment on why this fires
	// unconditionally on "ipam" block presence rather than only after a
	// confirmed ExecAdd.
	ipamDelegated bool
	ipamType      string
	ipamStdin     []byte
}

// Deliberately absent: deleting the VRF. tap.Delete below only removes this
// attachment's own tap device, which is genuinely private to it — but the
// VRF itself is shared by every attachment on this VPC on this node
// (internal/plumbing/vrf), and vrf.Add is idempotent, so a "vrfCreated" flag
// here could never distinguish "I created it" from "a sibling attachment
// already had." Deleting it on this attachment's own failed ADD could tear
// down a still-live sibling's VRF out from under it — see internal/cni's own
// resourceTracker.cleanup for the identical reasoning. Reclaiming it is
// exclusively galactic-router's GC controller's job.
func (rt *resourceTracker) cleanup() {
	// Release the IPAM allocation first — see internal/cni's own
	// resourceTracker for the full doc comment on why this fires
	// unconditionally on ipamDelegated alone. Interface/VRF cleanup is
	// shared with galactic-cni's own tracker, so it lives in
	// cnimaster.CleanupAttachment.
	if rt.ipamDelegated {
		if err := ipam.ExecDel(rt.ipamType, rt.ipamStdin); err != nil {
			slog.Error("Rollback: failed to release IPAM allocation", "err", err, "ipamType", rt.ipamType)
		} else {
			slog.Debug("Rollback: released IPAM allocation", "ipamType", rt.ipamType)
		}
	}

	cnimaster.CleanupAttachment(rt.vpc, rt.vpcAttachment, "tap", tap.Delete)
}
