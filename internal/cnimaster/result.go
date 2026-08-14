// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnimaster

import (
	"net"

	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/cniipam"
)

// AppendIPConfigs adds one IPConfig per allocated address family in ipRes
// (IPv6, and IPv4 when present) plus any default routes, all pointing at
// the given Interfaces index. No-op when ipRes is nil.
//
// Shared verbatim between galactic-veth (internal/cni) and galactic-tap
// (internal/cnitap): only the ifaceIndex and ipv4Mask each passes in differ
// (veth's guest interface vs tap's own host interface, /32 vs /25), never
// the logic itself.
func AppendIPConfigs(result *type100.Result, ipRes *cniipam.IPAMResult, ifaceIndex int, ipv4Mask net.IPMask) {
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
