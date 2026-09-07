// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/hostgw"
)

// buildResult constructs the CNI result, including IPAM data if configured.
func buildResult(
	pluginConf *PluginConf,
	ipRes *cniipam.IPAMResult,
	hostName, guestName string,
	hostMac, guestMac string,
	hostMTU, guestMTU int,
	netns string,
) *type100.Result {
	result := &type100.Result{
		CNIVersion: pluginConf.CNIVersion,
		Interfaces: []*type100.Interface{
			{
				Name:    hostName,
				Mac:     hostMac,
				Mtu:     hostMTU,
				Sandbox: "",
			},
			{
				Name:    guestName,
				Mac:     guestMac,
				Mtu:     guestMTU,
				Sandbox: netns,
			},
		},
	}
	cnimaster.AppendIPConfigs(result, ipRes, 1, net.CIDRMask(32, 32)) // index into Interfaces (guest veth)
	return result
}

// buildVethResult handles the veth-specific result: delegating the device move,
// allocating addresses, configuring the host gateway, reading back the guest
// interface, and printing. The BGP plugin chained next picks up everything it
// needs, the allocated addresses and that this was a veth attachment, from the
// printed result rather than a Go return value.
func buildVethResult(
	args *skel.CmdArgs,
	pluginConf *PluginConf,
	hostName, guestName string,
	hostMac string,
	hostMTU int,
) error {
	// Only delegate the move if the guest interface is still in the host
	// namespace. A prior attempt that moved it and then failed later must not
	// move it again.
	if _, linkErr := netlink.LinkByName(guestName); linkErr == nil {
		// Clean up a stale interface left in the container namespace by a
		// previous run: the delegate renames the moved interface, so a prior
		// run may have left that name behind.
		if err := cleanupContainerNetns(args.Netns, args.IfName); err != nil {
			return fmt.Errorf("cleanup container netns: %w", err)
		}
		if err := hostDevice("ADD", args, pluginConf); err != nil {
			return fmt.Errorf("host-device ADD: %w", err)
		}
	}

	// Configure the address on the guest interface inside the container
	// namespace. Whether to delegate at all is this plugin's own call, decided
	// solely by the ipam block's presence.
	var ipamResult *cniipam.IPAMResult
	if pluginConf.IPAM != nil {
		result, err := configureIPAM(args, pluginConf, args.IfName)
		if err != nil {
			return fmt.Errorf("configure IPAM: %w", err)
		}
		ipamResult = result
	}
	if ipamResult != nil {
		slog.Debug("ADD: IPAM allocated", "containerID", args.ContainerID,
			"ipv6Subnet", ipamResult.IPv6Subnet, "ipv6Gateway", ipamResult.IPv6Gateway,
			"ipv4Address", ipamResult.IPv4Address, "ipv4Gateway", ipamResult.IPv4Gateway)
	}

	// Read guest veth attributes inside the container netns.
	guestMac, guestMTU, err := readGuestInterface(args.Netns, args.IfName)
	if err != nil {
		return fmt.Errorf("read guest interface: %w", err)
	}
	guestHWAddr, err := net.ParseMAC(guestMac)
	if err != nil {
		return fmt.Errorf("parse guest interface MAC %q: %w", guestMac, err)
	}

	// Configure the host-side gateway address and VRF route before printing the
	// result: kernel-interface work this plugin owns.
	if err := hostgw.ConfigureHostGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult, guestHWAddr); err != nil {
		return fmt.Errorf("configure host gateway: %w", err)
	}

	result := buildResult(pluginConf, ipamResult, hostName, args.IfName, hostMac, guestMac, hostMTU, guestMTU, args.Netns)
	if err := types.PrintResult(result, pluginConf.CNIVersion); err != nil {
		return fmt.Errorf("print CNI result: %w", err)
	}

	return nil
}

// configureIPAM delegates allocation to whatever binary the config's ipam type
// names, then applies the returned addresses to the guest interface inside the
// container namespace, for both families when dual-stack.
//
// The plugin's own stdin is passed through as the delegate's netconf: it already
// contains the ipam block, plus everything else in this plugin's config, which
// the delegate ignores.
func configureIPAM(args *skel.CmdArgs, pluginConf *PluginConf, guestName string) (*cniipam.IPAMResult, error) {
	cniResult, err := ipam.ExecAdd(pluginConf.IPAM.Type, args.StdinData)
	if err != nil {
		return nil, fmt.Errorf("delegate to %s ADD: %w", pluginConf.IPAM.Type, err)
	}
	ipamResult, err := cniipam.ResultToIPAMResult(cniResult)
	if err != nil {
		return nil, fmt.Errorf("convert IPAM result: %w", err)
	}

	var ipv4Net *net.IPNet
	if ipamResult.IPv4Address != nil {
		ipv4Net = &net.IPNet{IP: ipamResult.IPv4Address, Mask: net.CIDRMask(32, 32)}
	}
	if err := configureInterfaceInNetns(
		args.Netns, guestName,
		ipamResult.IPv6Subnet, ipamResult.IPv6Gateway,
		ipv4Net, ipamResult.IPv4Gateway,
	); err != nil {
		return nil, err
	}

	return ipamResult, nil
}
