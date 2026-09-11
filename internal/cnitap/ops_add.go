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

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/hostconf"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/nadpatch"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/radv"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdAdd mirrors the veth plugin's own, minus everything specific to a guest
// namespace: no device-move delegation, no guest interface, no in-namespace
// address configuration. The VM manages its own interface. BGP and eBPF
// publishing is the next plugin's job, invoked by the runtime per conflist
// order.
func cmdAdd(args *skel.CmdArgs) (err error) {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

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

	// Reuses the k8sClient/podNamespace resolved above for the
	// chain-completeness check.
	nadCtx, nadCancel := context.WithTimeout(context.Background(), cnimaster.NADPatchTimeout)
	defer nadCancel()
	if err := nadpatch.AnnotateNAD(nadCtx, k8sClient, pluginConf.Name, podNamespace, hostName); err != nil {
		return fmt.Errorf("annotate NAD: %w", err)
	}

	// Termination routes are galactic-route's job now — chained next after
	// this plugin, when the attachment has any (see internal/cniroute).

	// Allocate addresses for the tap through delegation, only when the config
	// carries an ipam block. The VM manages its own guest interface; this plugin
	// configures the host side.
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

	// Configure the gateway address on the host tap and install the VRF route:
	// kernel-interface work this plugin owns.
	if err := hostgw.ConfigureHostGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult, nil); err != nil {
		return err
	}
	if ipamResult != nil && ipamResult.IPv6Gateway != nil {
		slog.Debug("ADD: host gateway configured", "name", hostName, "gateway", ipamResult.IPv6Gateway)

		// Record this attachment for periodic Router Advertisement resend by the
		// long-lived node daemon, rather than sending one from here: this
		// process exits as ADD returns, almost always before the guest has
		// booted far enough to be listening.
		if err := radv.RecordAttachment(radv.DefaultStateDir, hostName, hostMTU); err != nil {
			slog.Warn("ADD: failed to record attachment for router advertisement (non-fatal)",
				"err", err, "name", hostName)
		}
	}

	// Hand the sandbox to a Kata runtime-rs shim, when this attachment asked
	// for it. This is the last thing ADD does, so the file exists only once the
	// tap behind it is real and addressed. A failure is fatal to ADD, never
	// best-effort. See dan.Write.
	if danRequested(args.StdinData) {
		tracker.danDir, tracker.danSandboxID = cniConfig.DANDir, args.ContainerID
		if err := writeDANFile(cniConfig.DANDir, args.ContainerID, hostName, ipamResult, hostMTU); err != nil {
			return fmt.Errorf("emit DAN file: %w", err)
		}
		slog.Debug("ADD: DAN file written", "containerID", args.ContainerID,
			"dir", cniConfig.DANDir, "tap", hostName)
	}

	result := buildTapResult(pluginConf, ipamResult, hostName, hostMac, hostMTU)
	return types.PrintResult(result, pluginConf.CNIVersion)
}
