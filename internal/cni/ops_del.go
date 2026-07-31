// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
)

func cmdDel(args *skel.CmdArgs) error {
	// DEL is idempotent per the CNI spec: always return success.
	// Missing resources are not errors.
	slog.Info("DEL: starting", "containerID", args.ContainerID, "netns", args.Netns)

	// Parse config — if we can't parse it we still return success but
	// won't be able to clean up any resources.
	pluginConf, parseErr := parseConf(args.StdinData)
	if parseErr != nil {
		slog.Error("DEL: failed to parse CNI config, skipping cleanup", "err", parseErr,
			"containerID", args.ContainerID)
		result := &type100.Result{}
		_ = types.PrintResult(result, "1.0.0")
		return nil
	}
	vpc, vpcAtt := pluginConf.VPC, pluginConf.VPCAttachment

	// Deallocate the pod's IPAM subnet. This is pod-specific and safe to
	// release immediately. Applies to both veth and tap modes.
	if wantsIPAM(pluginConf) {
		if k8s, err := newK8sClient(); err == nil {
			deallocateIPAM(args, pluginConf, k8s)
		} else {
			slog.Warn("DEL: failed to create k8s client, skipping IPAM deallocation", "err", err,
				"containerID", args.ContainerID)
		}
	}

	// Explicitly flush the address/default-route galactic-cni's IPAM step
	// installed on the guest interface, ahead of host-device delegation.
	// hostDevice DEL's move of the guest veth end back out of the container
	// netns normally flushes this as a side effect of crossing a namespace
	// boundary, but that side effect never fires when args.Netns is the same
	// namespace the link already lives in (e.g. a hostNetwork pod with a
	// Multus secondary attachment) — the move is then a no-op, and the
	// leftover route survives indefinitely since there's no ephemeral
	// sandbox netns to reclaim it, wedging the next ADD with "file exists".
	// Only applies to veth mode; tap mode has no guest-side netns config.
	if pluginConf.InterfaceType == interfaceTypeVeth {
		if err := flushGuestNetnsConfig(args.Netns, args.IfName); err != nil {
			slog.Warn("DEL: failed to flush guest interface address/route, may still be in the netns",
				"err", err, "containerID", args.ContainerID, "netns", args.Netns)
		}
	}

	// Forward DEL to host-device delegated plugin (CNI spec §4). This moves
	// the guest veth end back out of the container netns and restores its
	// original (host-side) name. Only applies to veth mode; tap mode has no
	// host-device delegation.
	//
	// DEL must always return success per the CNI spec, so an error here
	// (e.g. the device was never moved into the netns because ADD failed
	// before reaching that step, or the netns is already gone) is logged
	// rather than propagated.
	if pluginConf.InterfaceType == interfaceTypeVeth {
		if err := hostDevice("DEL", args, pluginConf); err != nil {
			slog.Warn("DEL: host-device DEL failed, guest interface may still be in the netns",
				"err", err, "containerID", args.ContainerID, "netns", args.Netns)
		}
	}

	// Shared resources (VRF, veth/tap, routes, SRv6 ingress, BGPAdvertisement,
	// BGPVRFInstance) are keyed by (vpc, vpcAttachment) and may still be in use
	// by another pod. Deleting them here races with cmdAdd during pod restarts —
	// the old pod's DEL can destroy resources the new pod just created.
	//
	// The GC runs periodically and removes orphaned resources safely by checking
	// whether any live container still references them. See gc.CollectOrphanedCRDs
	// and gc.CollectOrphanedVRFs.
	slog.Info("DEL: skipping shared resource cleanup (handled by GC)",
		"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)

	result := &type100.Result{}
	_ = types.PrintResult(result, pluginConf.CNIVersion)

	return nil
}
