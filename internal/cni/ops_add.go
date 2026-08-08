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

	"go.datum.net/galactic/internal/cni/nadpatch"
	"go.datum.net/galactic/internal/cni/route"
	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdAdd uses a named return (err) so that the deferred selective rollback
// below always observes the real failure — see the doc comment on the
// original version of this function for why a named return matters here;
// still true with fewer branches. galactic-cni's own ADD ends by printing
// its own result and returning: BGP/SRv6/eBPF publish is galactic-bgp's
// job, invoked next by the CNI runtime per conflist order, not by this
// process.
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
		"namespace", namespace, "nodeName", nodeName)

	// Track resources for selective rollback on failure.
	tracker := &resourceTracker{
		vpc:           pluginConf.VPC,
		vpcAttachment: pluginConf.VPCAttachment,
	}
	// Record IPAM delegation intent up front, before configureIPAM (called
	// from buildVethResult below) ever runs — see resourceTracker's
	// ipamDelegated doc comment for why rollback needs this set
	// unconditionally on "ipam" block presence, not just after a
	// successful ExecAdd.
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

	if err := vrf.Add(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		return fmt.Errorf("add VRF: %w", err)
	}
	tracker.vrfCreated = true
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

	// Annotate the NAD with the host interface name. The NAD must already
	// exist (created by the external VPC operator); a missing or otherwise
	// unpatchable NAD is a hard failure.
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

	guestName := intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment)
	return buildVethResult(args, pluginConf, hostName, guestName, hostMac, hostMTU)
}
