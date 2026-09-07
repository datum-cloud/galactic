// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/hostconf"
	"go.datum.net/galactic/internal/nadpatch"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdAdd uses a named return so the deferred selective rollback always observes
// the real failure. It ends by printing its own result: BGP and eBPF publishing
// is the next plugin's job, invoked by the runtime per conflist order.
func cmdAdd(args *skel.CmdArgs) (err error) {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	// Validate a previous result when present. The preceding plugin should have
	// produced one with at least one interface or address; a structurally broken
	// one means a misconfigured chain this plugin should not silently ignore.
	if pluginConf.PrevResult != nil {
		if err := cnimaster.ValidatePrevResultAdd(pluginConf.PrevResult); err != nil {
			return &types.Error{Code: 6, Msg: fmt.Sprintf("prevResult validation in ADD: %v", err)}
		}
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return &types.Error{Code: 4, Msg: "NODE_NAME environment variable is not set"}
	}

	namespace := pluginConf.Namespace

	slog.Info("ADD: starting",
		"containerID", args.ContainerID, "netns", args.Netns, "ifName", args.IfName,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment,
		"namespace", namespace, "nodeName", nodeName)

	// Chain-completeness check, before any kernel state is created: a conflist
	// missing the BGP plugin would otherwise attach successfully with no path
	// to its VPC. The client and namespace are resolved here rather than at the
	// annotation site below, so a stale conflist fails ADD with nothing to roll
	// back yet.
	k8sClient, err := cnimaster.NewK8sClient()
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}
	podNamespace := nadpatch.ParsePodNamespace(args.Args)
	chainCtx, chainCancel := context.WithTimeout(context.Background(), cnimaster.NADPatchTimeout)
	defer chainCancel()
	if err := nadpatch.VerifyChainComplete(
		chainCtx, k8sClient, pluginConf.Name, podNamespace, hostconf.BGPPluginType,
	); err != nil {
		return &types.Error{Code: 7, Msg: fmt.Sprintf("chain completeness check: %v", err)}
	}

	// Track resources for selective rollback on failure.
	tracker := &resourceTracker{
		vpc:           pluginConf.VPC,
		vpcAttachment: pluginConf.VPCAttachment,
	}
	// Record the delegation intent up front, before allocation runs. Rollback
	// needs it set on the ipam block's presence alone, not only after a
	// successful delegated add.
	if pluginConf.IPAM != nil {
		tracker.ipamDelegated = true
		tracker.ipamType = pluginConf.IPAM.Type
		tracker.ipamStdin = args.StdinData
	}

	// Selective rollback: clean up only resources that were created.
	defer func() {
		if err != nil {
			slog.Error("ADD: failed, rolling back created resources", "err", err,
				"containerID", args.ContainerID, "vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			tracker.cleanup()
		}
	}()

	if err := vrf.Add(pluginConf.VPC); err != nil {
		return fmt.Errorf("add VRF: %w", err)
	}
	slog.Debug("ADD: VRF ready", "vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)

	if err := veth.Add(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.MTU); err != nil {
		return fmt.Errorf("add veth: %w", err)
	}

	hostName := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get host interface %q: %w", hostName, err)
	}
	hostMac := hostLink.Attrs().HardwareAddr.String()
	hostMTU := hostLink.Attrs().MTU
	slog.Debug("ADD: host interface ready", "name", hostName, "mac", hostMac, "mtu", hostMTU)

	// Annotate the attachment definition with the host interface name. It must
	// already exist, created by the external VPC operator, so a missing or
	// unpatchable one is a hard failure. Reuses the client and namespace
	// resolved above.
	nadCtx, nadCancel := context.WithTimeout(context.Background(), cnimaster.NADPatchTimeout)
	defer nadCancel()
	if err := nadpatch.AnnotateNAD(nadCtx, k8sClient, pluginConf.Name, podNamespace, hostName); err != nil {
		return fmt.Errorf("annotate NAD: %w", err)
	}

	// Termination routes are galactic-route's job now — chained next after
	// this plugin, when the attachment has any (see internal/cniroute).

	guestName := intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment)
	return buildVethResult(args, pluginConf, hostName, guestName, hostMac, hostMTU)
}
