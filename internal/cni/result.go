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
	"github.com/vishvananda/netlink"
)

// buildResult constructs the CNI result, including IPAM data if configured.
func buildResult(
	pluginConf *PluginConf,
	ipRes *ipamResult,
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
// given Interfaces index. ipv4Mask sets the prefix length reported for the
// IPv4 address — /32 for veth, /25 for tap (matching the host gateway mask
// installed by ipv4GatewayAddrParams, so downstream consumers such as
// kraftlet configure the guest with the same real subnet the host side
// advertises). No-op when ipRes is nil.
func appendIPConfigs(result *type100.Result, ipRes *ipamResult, ifaceIndex int, ipv4Mask net.IPMask) {
	if ipRes == nil {
		return
	}
	if ipRes.ipv6Subnet != nil {
		result.IPs = append(result.IPs, &type100.IPConfig{
			Address:   *ipRes.ipv6Subnet,
			Gateway:   ipRes.ipv6Gateway,
			Interface: type100.Int(ifaceIndex),
		})
	}
	if ipRes.ipv4Address != nil {
		result.IPs = append(result.IPs, &type100.IPConfig{
			Address:   net.IPNet{IP: ipRes.ipv4Address, Mask: ipv4Mask},
			Gateway:   ipRes.ipv4Gateway,
			Interface: type100.Int(ifaceIndex),
		})
	}
	if len(ipRes.routes) > 0 {
		result.Routes = make([]*types.Route, 0, len(ipRes.routes))
		for _, dst := range ipRes.routes {
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
) (*ipamResult, net.HardwareAddr, error) {
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
	var ipamResult *ipamResult
	if wantsIPAM(pluginConf) {
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

// buildTapResult constructs the CNI result for tap mode: a single host
// interface with optional IPAM data. The guest VM manages its own interface;
// the IP here describes the allocated subnet for BGP advertisement. The IPv4
// address is reported with a /25 mask, matching the mask
// ipv4GatewayAddrParams installs on the host side of the tap (see bgp.go).
func buildTapResult(
	pluginConf *PluginConf,
	ipRes *ipamResult,
	hostName, hostMac string,
	hostMTU int,
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
		},
	}
	appendIPConfigs(result, ipRes, 0, net.CIDRMask(25, 32)) // index into Interfaces (host tap)
	return result
}
