// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/nadpatch"
	"go.datum.net/galactic/internal/cni/route"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cnibgp"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdAdd mirrors internal/cni's own cmdAdd (see its doc comment for why the
// return is named), minus everything specific to a guest-side netns: no
// host-device delegation, no guest interface, no netns IP configuration.
// The VM manages its own interface entirely; galactic-tap-cni only
// configures the host side and publishes BGP state for it.
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
		namespace:     namespace,
	}

	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), cniTimeout)
	defer func() {
		if err != nil {
			slog.Error("ADD: failed, rolling back created resources", "err", err,
				"containerID", args.ContainerID, "vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			tracker.cleanup(rollbackCtx)
			rollbackCancel()
		}
	}()

	if err := vrf.Add(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		return fmt.Errorf("add VRF: %w", err)
	}
	tracker.vrfCreated = true
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
	tracker.k8s = k8sClient
	podNamespace := nadpatch.ParsePodNamespace(args.Args)
	if err := nadpatch.AnnotateNAD(rollbackCtx, k8sClient, pluginConf.Name, podNamespace, hostName); err != nil {
		return fmt.Errorf("annotate NAD: %w", err)
	}

	dev := hostName
	for _, termination := range pluginConf.Terminations {
		if err := route.Add(pluginConf.VPC, pluginConf.VPCAttachment, termination.Network, termination.Via, dev); err != nil {
			return fmt.Errorf("add route %s: %w", termination.Network, err)
		}
		tracker.routesCreated++
	}
	if tracker.routesCreated > 0 {
		slog.Debug("ADD: termination routes installed", "count", tracker.routesCreated, "dev", dev)
	}

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

	// Configure the gateway address on the host tap and install the VRF route.
	if err := cnibgp.ConfigureHostGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult, nil); err != nil {
		return err
	}
	if ipamResult != nil && ipamResult.IPv6Gateway != nil {
		slog.Debug("ADD: host gateway configured", "name", hostName, "gateway", ipamResult.IPv6Gateway)
	}

	result := buildTapResult(pluginConf, ipamResult, hostName, hostMac, hostMTU)
	if err := types.PrintResult(result, pluginConf.CNIVersion); err != nil {
		return fmt.Errorf("print CNI result: %w", err)
	}

	vpcHex, err := intf.Base62ToHex(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("decode VPC: %w", err)
	}

	if tracker.k8s == nil {
		return errors.New("k8s client not set in tracker")
	}
	slog.Debug("ADD: publishing BGP state", "containerID", args.ContainerID)
	pubResult, err := cnibgp.PublishBGPStateK8s(
		args, cnibgp.PublishConfig{VPC: pluginConf.VPC, VPCAttachment: pluginConf.VPCAttachment, InterfaceType: "tap"},
		nodeName, namespace, ipamResult, vpcHex, tracker.k8s)
	tracker.vrfInstanceCreated = pubResult.VRFInstanceCreated
	tracker.advCreated = pubResult.AdvertisementCreated
	tracker.ebpfRegistered = pubResult.EBPFRegistered
	tracker.ebpfBlock = pubResult.EBPFBlock
	tracker.ebpfArgument = pubResult.EBPFArgument
	return err
}
