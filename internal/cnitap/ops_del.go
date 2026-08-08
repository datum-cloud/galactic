// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/cniipam"
)

// cmdDel mirrors internal/cni's own cmdDel, minus everything guest-netns
// specific (no flushGuestNetnsConfig, no host-device DEL delegation — tap
// mode never touches a container netns at all).
func cmdDel(args *skel.CmdArgs) error {
	// DEL is idempotent per the CNI spec: always return success.
	slog.Info("DEL: starting", "containerID", args.ContainerID, "netns", args.Netns)

	pluginConf, parseErr := parseConf(args.StdinData)
	if parseErr != nil {
		slog.Error("DEL: failed to parse CNI config, skipping cleanup", "err", parseErr,
			"containerID", args.ContainerID)
		result := &type100.Result{}
		_ = types.PrintResult(result, "1.0.0")
		return nil
	}
	vpc, vpcAtt := pluginConf.VPC, pluginConf.VPCAttachment

	cfg := allocConfig(pluginConf)
	if cniipam.WantsIPAM(cfg) {
		if k8s, err := newK8sClient(); err == nil {
			cniipam.Deallocate(args, cfg, k8s)
		} else {
			slog.Warn("DEL: failed to create k8s client, skipping IPAM deallocation", "err", err,
				"containerID", args.ContainerID)
		}
	}

	// Shared resources (VRF, tap, routes, SRv6 ingress, BGPAdvertisement,
	// BGPVRFInstance) are keyed by (vpc, vpcAttachment) and may still be in
	// use by another VM. Deleting them here races with cmdAdd during
	// restarts, so cleanup is left to galactic-router's GC controller — see
	// internal/cni's own cmdDel for the full reasoning.
	slog.Info("DEL: skipping shared resource cleanup (handled by GC)",
		"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)

	result := &type100.Result{}
	_ = types.PrintResult(result, pluginConf.CNIVersion)

	return nil
}
