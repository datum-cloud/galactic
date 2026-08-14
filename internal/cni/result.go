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

// buildVethResult handles veth-specific result building: host-device
// delegation, IPAM, host gateway configuration, guest interface reading,
// and result printing. galactic-bgp (chained next by the runtime) picks up
// everything it needs — the allocated addresses, and that this was a veth
// attachment — from the result this prints, not from a Go-level return
// value.
func buildVethResult(
	args *skel.CmdArgs,
	pluginConf *PluginConf,
	hostName, guestName string,
	hostMac string,
	hostMTU int,
) error {
	// Only call host-device ADD if the guest interface is still in the host
	// namespace. If a prior attempt already moved it to the container netns but
	// failed at a later step, we must not try to move it again.
	if _, linkErr := netlink.LinkByName(guestName); linkErr == nil {
		// Clean up any stale interface in the container netns left by a
		// previous run. The host-device plugin renames the moved interface
		// to args.IfName, so a prior run may have left that name behind.
		if err := cleanupContainerNetns(args.Netns, args.IfName); err != nil {
			return fmt.Errorf("cleanup container netns: %w", err)
		}
		if err := hostDevice("ADD", args, pluginConf); err != nil {
			return fmt.Errorf("host-device ADD: %w", err)
		}
	}

	// Configure IP address on the guest interface inside the container netns.
	// Delegating at all is this plugin's own call, decided solely by "ipam"
	// block presence — no config field or env var elsewhere can override
	// that (see internal/cniipam's doc comment for the explicit contract).
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

	// Configure the host-side gateway address and VRF route before printing
	// the result — kernel-interface work this plugin owns (see
	// internal/hostgw's doc comment for why galactic-bgp no longer does
	// this itself).
	if err := hostgw.ConfigureHostGateway(pluginConf.VPC, pluginConf.VPCAttachment, ipamResult, guestHWAddr); err != nil {
		return fmt.Errorf("configure host gateway: %w", err)
	}

	result := buildResult(pluginConf, ipamResult, hostName, args.IfName, hostMac, guestMac, hostMTU, guestMTU, args.Netns)
	if err := types.PrintResult(result, pluginConf.CNIVersion); err != nil {
		return fmt.Errorf("print CNI result: %w", err)
	}

	return nil
}

// configureIPAM delegates IPAM allocation to whatever binary pluginConf's
// own "ipam.type" names (per the CNI IPAM delegation protocol — see
// github.com/containernetworking/plugins/pkg/ipam.ExecAdd), then applies
// the returned addresses to the guest interface inside the container
// network namespace with both families (when dual-stack). args.StdinData
// is passed straight through as the delegate's own netconf: it already
// contains the "ipam" block (plus everything else in this plugin's own
// config, which the delegate simply ignores).
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
