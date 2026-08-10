// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cniipam"
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
	appendIPConfigs(result, ipRes, 1, net.CIDRMask(32, 32)) // index into Interfaces (guest veth)
	return result
}

// appendIPConfigs adds one IPConfig per allocated address family in ipRes
// (IPv6, and IPv4 when present) plus any default routes, all pointing at the
// given Interfaces index. No-op when ipRes is nil.
func appendIPConfigs(result *type100.Result, ipRes *cniipam.IPAMResult, ifaceIndex int, ipv4Mask net.IPMask) {
	if ipRes == nil {
		return
	}
	if ipRes.IPv6Subnet != nil {
		result.IPs = append(result.IPs, &type100.IPConfig{
			Address:   *ipRes.IPv6Subnet,
			Gateway:   ipRes.IPv6Gateway,
			Interface: type100.Int(ifaceIndex),
		})
	}
	if ipRes.IPv4Address != nil {
		result.IPs = append(result.IPs, &type100.IPConfig{
			Address:   net.IPNet{IP: ipRes.IPv4Address, Mask: ipv4Mask},
			Gateway:   ipRes.IPv4Gateway,
			Interface: type100.Int(ifaceIndex),
		})
	}
	if len(ipRes.Routes) > 0 {
		result.Routes = make([]*types.Route, 0, len(ipRes.Routes))
		for _, dst := range ipRes.Routes {
			result.Routes = append(result.Routes, &types.Route{
				Dst: *dst,
			})
		}
	}
}

// buildVethResult handles veth-specific result building: host-device
// delegation, IPAM, guest interface reading, and result printing.
// Returns the IPAM result for BGP advertisement, or nil if no IPAM.
func buildVethResult(
	args *skel.CmdArgs,
	pluginConf *PluginConf,
	hostName, guestName string,
	hostMac string,
	hostMTU int,
) (*cniipam.IPAMResult, net.HardwareAddr, error) {
	// Only call host-device ADD if the guest interface is still in the host
	// namespace. If a prior attempt already moved it to the container netns but
	// failed at a later step, we must not try to move it again.
	if _, linkErr := netlink.LinkByName(guestName); linkErr == nil {
		// Clean up any stale interface in the container netns left by a
		// previous run. The host-device plugin renames the moved interface
		// to args.IfName, so a prior run may have left that name behind.
		if err := cleanupContainerNetns(args.Netns, args.IfName); err != nil {
			return nil, nil, fmt.Errorf("cleanup container netns: %w", err)
		}
		if err := hostDevice("ADD", args, pluginConf); err != nil {
			return nil, nil, fmt.Errorf("host-device ADD: %w", err)
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
			return nil, nil, fmt.Errorf("configure IPAM: %w", err)
		}
		ipamResult = result
	}

	// Read guest veth attributes inside the container netns.
	guestMac, guestMTU, err := readGuestInterface(args.Netns, args.IfName)
	if err != nil {
		return nil, nil, fmt.Errorf("read guest interface: %w", err)
	}
	guestHWAddr, err := net.ParseMAC(guestMac)
	if err != nil {
		return nil, nil, fmt.Errorf("parse guest interface MAC %q: %w", guestMac, err)
	}
	result := buildResult(pluginConf, ipamResult, hostName, args.IfName, hostMac, guestMac, hostMTU, guestMTU, args.Netns)
	if err := types.PrintResult(result, pluginConf.CNIVersion); err != nil {
		return nil, nil, fmt.Errorf("print CNI result: %w", err)
	}

	return ipamResult, guestHWAddr, nil
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
