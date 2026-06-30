// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"

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
	if ipRes != nil {
		ipConfig := &type100.IPConfig{
			Address:   *ipRes.subnet,
			Gateway:   ipRes.gateway,
			Interface: type100.Int(1), // index into Interfaces (guest veth)
		}
		result.IPs = []*type100.IPConfig{ipConfig}
		if len(ipRes.routes) > 0 {
			result.Routes = make([]*types.Route, 0, len(ipRes.routes))
			for _, dst := range ipRes.routes {
				result.Routes = append(result.Routes, &types.Route{
					Dst: *dst,
				})
			}
		}
	}
	return result
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
) (*ipamResult, error) {
	// Only call host-device ADD if the guest interface is still in the host
	// namespace. If a prior attempt already moved it to the container netns but
	// failed at a later step, we must not try to move it again.
	if _, linkErr := netlink.LinkByName(guestName); linkErr == nil {
		// Clean up any stale interface in the container netns left by a
		// previous run. The host-device plugin renames the moved interface
		// to args.IfName, so a prior run may have left that name behind.
		if err := cleanupContainerNetns(args.Netns, args.IfName); err != nil {
			return nil, fmt.Errorf("cleanup container netns: %w", err)
		}
		if err := hostDevice("ADD", args, pluginConf); err != nil {
			return nil, fmt.Errorf("host-device ADD: %w", err)
		}
	}

	// Configure IP address on the guest interface inside the container netns.
	var ipamResult *ipamResult
	if pluginConf.IPAM.Type != "" || enableLocalIPAM {
		result, err := configureIPAM(args, pluginConf, args.IfName)
		if err != nil {
			return nil, fmt.Errorf("configure IPAM: %w", err)
		}
		ipamResult = result
	}

	// Read guest veth attributes inside the container netns.
	guestMac, guestMTU, err := readGuestInterface(args.Netns, args.IfName)
	if err != nil {
		return nil, fmt.Errorf("read guest interface: %w", err)
	}
	result := buildResult(pluginConf, ipamResult, hostName, args.IfName, hostMac, guestMac, hostMTU, guestMTU, args.Netns)
	if err := types.PrintResult(result, cniVersion100); err != nil {
		return nil, fmt.Errorf("print CNI result: %w", err)
	}

	return ipamResult, nil
}

// buildTapResult constructs the CNI result for tap mode: a single host
// interface with no IPAM or guest endpoint.
func buildTapResult(
	pluginConf *PluginConf,
	hostName, hostMac string,
	hostMTU int,
) *type100.Result {
	return &type100.Result{
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
}
