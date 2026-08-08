// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"net"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/cniipam"
)

// buildTapResult constructs the CNI result for tap mode: a single host
// interface with optional IPAM data. The guest VM manages its own
// interface; the IP here describes the allocated subnet for BGP
// advertisement. The IPv4 address is reported with a /25 mask, matching the
// mask cnibgp.ConfigureHostGateway installs on the host side of the tap.
func buildTapResult(
	pluginConf *PluginConf,
	ipRes *cniipam.IPAMResult,
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

// appendIPConfigs adds one IPConfig per allocated address family in ipRes
// (IPv6, and IPv4 when present) plus any default routes, all pointing at
// the given Interfaces index. No-op when ipRes is nil.
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
