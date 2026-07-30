// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/route"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdAdd uses a named return (err) so that the deferred selective rollback
// below always observes the real failure: several branches check errors via
// "if err := f(); err != nil" inside nested if/switch blocks, which declares
// a block-scoped err that would otherwise shadow this function's err and
// leave the deferred rollback thinking the call succeeded. A plain
// "return expr" always assigns expr to a named result, regardless of that
// local shadowing, so naming the return here is what makes rollback fire on
// every failure path instead of just the ones using top-level "x, err := f()".
func cmdAdd(args *skel.CmdArgs) (err error) {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	// Validate prevResult structure when present. The preceding plugin in the
	// CNI chain should have produced a result with at least one interface or IP
	// assignment. A nil or structurally broken prevResult indicates a mis-
	// configured chain that galactic-cni should not silently ignore.
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
		"interfaceType", pluginConf.InterfaceType, "namespace", namespace, "nodeName", nodeName)

	// Track resources for selective rollback on failure.
	tracker := &resourceTracker{
		vpc:           pluginConf.VPC,
		vpcAttachment: pluginConf.VPCAttachment,
		ifaceType:     pluginConf.InterfaceType,
		namespace:     namespace,
	}

	// Selective rollback: clean up only resources that were created.
	// We need a context for k8s operations in rollback; the k8s client
	// will be populated by publishBGPState before it's needed.
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

	// Create the appropriate interface type (veth or tap).
	switch pluginConf.InterfaceType {
	case interfaceTypeVeth:
		if err := veth.Add(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.MTU); err != nil {
			return fmt.Errorf("add veth: %w", err)
		}
	case interfaceTypeTap:
		if err := tap.Add(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.MTU); err != nil {
			return fmt.Errorf("add tap: %w", err)
		}
	}

	hostName := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("get host interface %q: %w", hostName, err)
	}
	hostMac := hostLink.Attrs().HardwareAddr.String()
	hostMTU := hostLink.Attrs().MTU
	slog.Debug("ADD: host interface ready", "name", hostName, "mac", hostMac, "mtu", hostMTU)

	// Annotate the NAD with the host interface name. The NAD must already
	// exist (created by the external VPC operator); a missing or otherwise
	// unpatchable NAD is a hard failure.
	k8sClient, err := newK8sClient()
	if err != nil {
		return fmt.Errorf("create k8s client: %w", err)
	}
	tracker.k8s = k8sClient
	podNamespace := parsePodNamespace(args.Args)
	tracker.podNamespace = podNamespace
	if err := annotateNAD(rollbackCtx, k8sClient, pluginConf.Name, podNamespace, hostName); err != nil {
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

	// Host-device delegation and IPAM are veth-only.
	// In tap mode the guest VM manages its own networking.
	var ipamResult *ipamResult
	var guestName string // empty for tap: the guest VM manages its own interface, there is no galactic-owned guest device
	switch pluginConf.InterfaceType {
	case interfaceTypeVeth:
		guestName = intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment)
		ipamResult, err = buildVethResult(args, pluginConf, hostName, guestName, hostMac, hostMTU)
		if err != nil {
			return err
		}
		if ipamResult != nil {
			slog.Debug("ADD: IPAM allocated", "containerID", args.ContainerID,
				"ipv6Subnet", ipamResult.ipv6Subnet, "ipv6Gateway", ipamResult.ipv6Gateway,
				"ipv4Address", ipamResult.ipv4Address, "ipv4Gateway", ipamResult.ipv4Gateway)
		}
	case interfaceTypeTap:
		return cmdAddTap(args, pluginConf, tracker, nodeName, namespace, podNamespace, hostName, hostMac, hostMTU)
	}

	err = applyVPCAttachmentRetrying(args, pluginConf, podNamespace, nodeName, hostName, guestName, ipamResult, tracker)
	if err != nil {
		return err
	}
	slog.Debug("ADD: publishing BGP state", "containerID", args.ContainerID, "interfaceType", pluginConf.InterfaceType)
	return publishBGPState(args, pluginConf, nodeName, namespace, ipamResult, tracker)
}

// cmdAddTap finishes cmdAdd's tap-mode path: IPAM allocation, host gateway
// configuration, the CNI result, and BGP/VPCAttachment state publishing.
// Split out of cmdAdd to keep its cyclomatic complexity in check — this is
// pure extraction, not a behavior change.
func cmdAddTap(
	args *skel.CmdArgs, pluginConf *PluginConf, tracker *resourceTracker,
	nodeName, namespace, podNamespace, hostName, hostMac string, hostMTU int,
) error {
	// Allocate IPAM for the tap interface (same as veth).
	// The VM manages its own guest interface; the CNI only configures the host side.
	ipamResult, err := allocateIPAM(args, pluginConf)
	if err != nil {
		return fmt.Errorf("allocate IPAM: %w", err)
	}
	if ipamResult != nil {
		slog.Debug("ADD: IPAM allocated", "containerID", args.ContainerID,
			"ipv6Subnet", ipamResult.ipv6Subnet, "ipv6Gateway", ipamResult.ipv6Gateway,
			"ipv4Address", ipamResult.ipv4Address, "ipv4Gateway", ipamResult.ipv4Gateway)
	}

	// Configure the gateway address on the host tap and install the VRF route.
	if err := configureHostGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult); err != nil {
		return err
	}
	if ipamResult != nil && ipamResult.ipv6Gateway != nil {
		slog.Debug("ADD: host gateway configured", "name", hostName, "gateway", ipamResult.ipv6Gateway)
	}

	// Print the CNI result with IP info.
	result := buildTapResult(pluginConf, ipamResult, hostName, hostMac, hostMTU)
	if err := types.PrintResult(result, pluginConf.CNIVersion); err != nil {
		return fmt.Errorf("print CNI result: %w", err)
	}

	// Decode VPC/VRFID for BGP state publish.
	vpcHex, err := intf.Base62ToHex(pluginConf.VPC)
	if err != nil {
		return fmt.Errorf("decode VPC: %w", err)
	}
	vrfID, err := vrfIDFromAttachment(pluginConf.VPCAttachment)
	if err != nil {
		return fmt.Errorf("decode VPCAttachment: %w", err)
	}

	// Publish BGP state (SRv6 ingress + BGP CRDs).
	if tracker.k8s == nil {
		return errors.New("k8s client not set in tracker")
	}
	// guestName is always empty in tap mode: the guest VM manages its own
	// interface, there is no galactic-owned guest device.
	if err := applyVPCAttachmentRetrying(
		args, pluginConf, podNamespace, nodeName, hostName, "", ipamResult, tracker,
	); err != nil {
		return err
	}
	slog.Debug("ADD: publishing BGP state", "containerID", args.ContainerID, "interfaceType", interfaceTypeTap)
	return publishBGPStateK8s(args, pluginConf, nodeName, namespace, ipamResult, vpcHex, vrfID, tracker.k8s, tracker)
}

// applyVPCAttachmentRetrying wraps applyVPCAttachment in retryK8sOps, shared
// by both cmdAdd's veth tail and cmdAddTap.
func applyVPCAttachmentRetrying(
	args *skel.CmdArgs, pluginConf *PluginConf, podNamespace, nodeName, hostName, guestName string,
	ipamResult *ipamResult, tracker *resourceTracker,
) error {
	err := retryK8sOps(cniTimeout, func(ctx context.Context) error {
		return applyVPCAttachment(
			ctx, tracker.k8s, args, pluginConf, podNamespace, nodeName, hostName, guestName, ipamResult, tracker,
		)
	})
	if err != nil {
		return fmt.Errorf("apply VPCAttachment: %w", err)
	}
	return nil
}
