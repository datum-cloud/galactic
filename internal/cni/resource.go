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

// resourceTracker tracks resources created during cmdAdd for selective
// rollback. galactic-veth is veth-only, and its ADD only ever creates the
// VRF, the veth pair, and (if delegated) an IPAM allocation — BGP/SRv6/eBPF
// publish is galactic-bgp's own, separately chain-invoked plugin now, with
// its own smaller tracker (internal/cnibgp); termination routes are
// galactic-route's own, with its own smaller tracker (internal/cniroute);
// so this one no longer needs to know anything about either.
type resourceTracker struct {
	vpc, vpcAttachment string

	// ipamDelegated, ipamType, and ipamStdin record enough to release the
	// IPAM allocation during rollback. Set as soon as pluginConf.IPAM != nil
	// is known (before configureIPAM/ipam.ExecAdd is even attempted) rather
	// than only after a successful ExecAdd: ipam.ExecDel is idempotent per
	// the CNI IPAM delegation protocol (galactic-ipam's own cmdDel no-ops
	// when it finds no allocation for the containerID), so calling it
	// unconditionally whenever an "ipam" block was configured is safe and
	// covers every failure path, including ones where ExecAdd itself never
	// ran. Without this, a failed ADD that got past IPAM permanently burns
	// an address/subnet out of the pool — the on-disk marker file has no
	// implicit teardown the way the old in-memory-only allocator did.
	ipamDelegated bool
	ipamType      string
	ipamStdin     []byte
}

// cleanup rolls back all tracked resources in reverse creation order.
// Errors are logged but never returned — the caller already has a failure.
// Takes no context: unlike before this split, the only non-kernel call left
// here is ipam.ExecDel, which (like ExecAdd) shells out to the delegated
// plugin binary rather than making a k8s API call (BGP CRD/eBPF rollback is
// galactic-bgp's own tracker now).
//
// Deliberately absent: deleting the VRF. veth.Delete below only removes
// this attachment's own host/guest veth pair, which is genuinely private to
// it — but the VRF itself is now shared by every attachment on this VPC on
// this node (internal/plumbing/vrf keys it by VPC alone), and vrf.Add is
// idempotent, so there's no way to distinguish "I created it" from "a
// sibling attachment already had." Deleting it on this attachment's own
// failed ADD could tear down a still-live sibling's VRF out from under it —
// the same reasoning internal/cnibgp's resourceTracker applies to the
// BGPVRFInstance CRD and eBPF vrf_table entry. Reclaiming it is exclusively
// galactic-router's GC controller's job, once it has confirmed via every
// BGPAdvertisement for this VPC/node that none remain.
func (rt *resourceTracker) cleanup() {
	// Release the IPAM allocation first (if pluginConf carried an "ipam"
	// block at all — see the ipamDelegated field doc comment for why this
	// fires unconditionally on that alone, not just after a confirmed
	// ExecAdd). Interface/VRF cleanup is shared with galactic-tap's own
	// tracker, so it lives in cnimaster.CleanupAttachment.
	if rt.ipamDelegated {
		if err := ipam.ExecDel(rt.ipamType, rt.ipamStdin); err != nil {
			slog.Error("Rollback: failed to release IPAM allocation", "err", err, "ipamType", rt.ipamType)
		} else {
			slog.Debug("Rollback: released IPAM allocation", "ipamType", rt.ipamType)
		}
	}

	cnimaster.CleanupAttachment(rt.vpc, rt.vpcAttachment, "veth", veth.Delete)
}
