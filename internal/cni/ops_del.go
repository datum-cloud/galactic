// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"

	"go.datum.net/galactic/internal/cni/veth"
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
	// release immediately. Delegating at all (or not) is entirely
	// pluginConf.IPAM's own presence — no k8s client needed here at all
	// now that galactic-ipam's own DEL looks its allocation up locally
	// (see internal/cniipam's doc comment).
	if pluginConf.IPAM != nil {
		if err := ipam.ExecDel(pluginConf.IPAM.Type, args.StdinData); err != nil {
			slog.Warn("DEL: IPAM delegation failed, allocation may not have been released", "err", err,
				"containerID", args.ContainerID)
		}
	}

	// Explicitly flush the address/default-route galactic-veth's IPAM step
	// installed on the guest interface, ahead of host-device delegation.
	// hostDevice DEL's move of the guest veth end back out of the container
	// netns normally flushes this as a side effect of crossing a namespace
	// boundary, but that side effect never fires when args.Netns is the same
	// namespace the link already lives in (e.g. a hostNetwork pod with a
	// Multus secondary attachment) — the move is then a no-op, and the
	// leftover route survives indefinitely since there's no ephemeral
	// sandbox netns to reclaim it, wedging the next ADD with "file exists".
	if err := flushGuestNetnsConfig(args.Netns, args.IfName); err != nil {
		slog.Warn("DEL: failed to flush guest interface address/route, may still be in the netns",
			"err", err, "containerID", args.ContainerID, "netns", args.Netns)
	}

	// Forward DEL to host-device delegated plugin (CNI spec §4). This moves
	// the guest veth end back out of the container netns and restores its
	// original (host-side) name.
	//
	// DEL must always return success per the CNI spec, so an error here
	// (e.g. the device was never moved into the netns because ADD failed
	// before reaching that step, or the netns is already gone) is logged
	// rather than propagated.
	if err := hostDevice("DEL", args, pluginConf); err != nil {
		slog.Warn("DEL: host-device DEL failed, guest interface may still be in the netns",
			"err", err, "containerID", args.ContainerID, "netns", args.Netns)
	}

	// Delete this attachment's own host/guest veth pair. Unlike the VRF and
	// BGP CRDs below, the veth pair is genuinely private to this attachment
	// (see resourceTracker.cleanup's doc comment) — no sibling pod can ever
	// still be depending on it, so there is no ADD-race to defer to GC for.
	// Deleting the host end removes both ends of the pair regardless of
	// which netns the guest end currently lives in, so this reclaims the
	// interface even when the host-device DEL step above failed or no-op'd.
	if err := veth.Delete(vpc, vpcAtt); err != nil {
		slog.Warn("DEL: failed to delete host/guest veth pair", "err", err,
			"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)
	}

	// Shared resources (VRF, BGPAdvertisement, BGPVRFInstance) are keyed by
	// (vpc, vpcAttachment) or (vpc, node) and may still be in use by another
	// pod. Deleting them here races with cmdAdd during pod restarts — the old
	// pod's DEL can destroy resources the new pod just created.
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
