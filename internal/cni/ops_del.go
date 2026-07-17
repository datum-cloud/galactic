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
		_ = types.PrintResult(result, cniVersion100)
		return nil
	}
	vpc, vpcAtt := pluginConf.VPC, pluginConf.VPCAttachment

	// Deallocate the pod's IPAM subnet. This is pod-specific and safe to
	// release immediately. Applies to both veth and tap modes.
	hasIPAM := (pluginConf.IPAM != nil && pluginConf.IPAM.Type != "") || enableLocalIPAM
	if hasIPAM {
		if k8s, err := newK8sClient(); err == nil {
			deallocateIPAM(args, pluginConf, k8s)
		} else {
			slog.Warn("DEL: failed to create k8s client, skipping IPAM deallocation", "err", err,
				"containerID", args.ContainerID)
		}
	}

	// Forward DEL to host-device delegated plugin (CNI spec §4).
	// host-device DEL is idempotent — missing devices are not errors.
	// Only applies to veth mode; tap mode has no host-device delegation.
	if pluginConf.InterfaceType == interfaceTypeVeth {
		_ = hostDevice("DEL", args, pluginConf)
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
	_ = types.PrintResult(result, cniVersion100)

	return nil
}
