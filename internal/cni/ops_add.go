// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"errors"
	"fmt"
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

func cmdAdd(args *skel.CmdArgs) error {
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
			return fmt.Errorf("prevResult validation in ADD: %w", err)
		}
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return errors.New("NODE_NAME environment variable is not set")
	}

	namespace := pluginConf.Namespace

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
			tracker.cleanup(rollbackCtx)
			rollbackCancel()
		}
	}()

	if err := vrf.Add(pluginConf.VPC, pluginConf.VPCAttachment); err != nil {
		return fmt.Errorf("add VRF: %w", err)
	}
	tracker.vrfCreated = true

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

	dev := hostName
	for _, termination := range pluginConf.Terminations {
		if err := route.Add(pluginConf.VPC, pluginConf.VPCAttachment, termination.Network, termination.Via, dev); err != nil {
			return fmt.Errorf("add route %s: %w", termination.Network, err)
		}
		tracker.routesCreated++
	}

	// Host-device delegation and IPAM are veth-only.
	// In tap mode the guest VM manages its own networking.
	var ipamResult *ipamResult
	switch pluginConf.InterfaceType {
	case interfaceTypeVeth:
		guestName := intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment)
		ipamResult, err = buildVethResult(args, pluginConf, hostName, guestName, hostMac, hostMTU)
		if err != nil {
			return err
		}
	case interfaceTypeTap:
		// Allocate IPAM for the tap interface (same as veth).
		// The VM manages its own guest interface; the CNI only configures the host side.
		ipamResult, err = allocateIPAM(args, pluginConf)
		if err != nil {
			return fmt.Errorf("allocate IPAM: %w", err)
		}

		// Configure the gateway address on the host tap and install the VRF route.
		if err := configureHostGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult); err != nil {
			return err
		}

		// Print the CNI result with IP info.
		result := buildTapResult(pluginConf, ipamResult, hostName, hostMac, hostMTU)
		if err := types.PrintResult(result, cniVersion100); err != nil {
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
		k8s, err := newK8sClient()
		if err != nil {
			return err
		}
		tracker.k8s = k8s
		return publishBGPStateK8s(args, pluginConf, nodeName, namespace, ipamResult, vpcHex, vrfID, k8s, tracker)
	}

	return publishBGPState(args, pluginConf, nodeName, namespace, ipamResult, tracker)
}
