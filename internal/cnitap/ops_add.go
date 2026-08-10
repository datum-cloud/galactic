// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/hostgw"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/nadpatch"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdAdd mirrors internal/cni's own cmdAdd, minus everything specific to a
// guest-side netns: no host-device delegation, no guest interface, no
// netns IP configuration. The VM manages its own interface entirely.
// BGP/SRv6/eBPF publish is galactic-bgp's job, invoked next by the CNI
// runtime per conflist order, not by this process.
func cmdAdd(args *skel.CmdArgs) (err error) {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	if pluginConf.PrevResult != nil {
		if err := validatePrevResultAdd(pluginConf.PrevResult); err != nil {
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

	tracker := &resourceTracker{
		vpc:           pluginConf.VPC,
		vpcAttachment: pluginConf.VPCAttachment,
	}
	// Record IPAM delegation intent up front, before the ExecAdd call
	// below ever runs — see resourceTracker's ipamDelegated doc comment.
	if pluginConf.IPAM != nil {
		tracker.ipamDelegated = true
		tracker.ipamType = pluginConf.IPAM.Type
		tracker.ipamStdin = args.StdinData
	}

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

	if err := tap.Add(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.MTU); err != nil {
		return fmt.Errorf("add tap: %w", err)
	}

	hostName := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get host interface %q: %w", hostName, err)
	}
	hostMac := hostLink.Attrs().HardwareAddr.String()
	hostMTU := hostLink.Attrs().MTU
	slog.Debug("ADD: host interface ready", "name", hostName, "mac", hostMac, "mtu", hostMTU)

	k8sClient, err := newK8sClient()
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}
	podNamespace := nadpatch.ParsePodNamespace(args.Args)
	nadCtx, nadCancel := context.WithTimeout(context.Background(), cniTimeout)
	defer nadCancel()
	if err := nadpatch.AnnotateNAD(nadCtx, k8sClient, pluginConf.Name, podNamespace, hostName); err != nil {
		return fmt.Errorf("annotate NAD: %w", err)
	}

	// Termination routes are galactic-route's job now — chained next after
	// this plugin, when the attachment has any (see internal/cniroute).

	// Allocate IPAM for the tap interface via delegation (only if pluginConf
	// carries an "ipam" block at all — see internal/cniipam's doc comment
	// for the explicit contract). The VM manages its own guest interface;
	// this plugin only configures the host side.
	var ipamResult *cniipam.IPAMResult
	if pluginConf.IPAM != nil {
		cniResult, err := ipam.ExecAdd(pluginConf.IPAM.Type, args.StdinData)
		if err != nil {
			return fmt.Errorf("delegate to %s ADD: %w", pluginConf.IPAM.Type, err)
		}
		ipamResult, err = cniipam.ResultToIPAMResult(cniResult)
		if err != nil {
			return fmt.Errorf("convert IPAM result: %w", err)
		}
	}
	if ipamResult != nil {
		slog.Debug("ADD: IPAM allocated", "containerID", args.ContainerID,
			"ipv6Subnet", ipamResult.IPv6Subnet, "ipv6Gateway", ipamResult.IPv6Gateway,
			"ipv4Address", ipamResult.IPv4Address, "ipv4Gateway", ipamResult.IPv4Gateway)
	}

	// Configure the gateway address on the host tap and install the VRF
	// route — kernel-interface work this plugin owns (see
	// internal/cni/hostgw's doc comment).
	if err := hostgw.ConfigureHostGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult, nil); err != nil {
		return err
	}
	if ipamResult != nil && ipamResult.IPv6Gateway != nil {
		slog.Debug("ADD: host gateway configured", "name", hostName, "gateway", ipamResult.IPv6Gateway)
	}

	result := buildTapResult(pluginConf, ipamResult, hostName, hostMac, hostMTU)
	return types.PrintResult(result, pluginConf.CNIVersion)
}
