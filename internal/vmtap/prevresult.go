// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"fmt"

	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
)

// resolveRedirectInterface reads ifName's state out of pluginConf's already-
// parsed prevResult (MAC, link MTU) and, for the route MTU Cilium may have
// adjusted independently of the link MTU, out of the kernel routing table.
// Callers must already be running inside the target network namespace.
//
// Per .local/kraftlet-cilium-tap-plan.md section 1, this never mutates
// ifName — it is read-only.
func resolveRedirectInterface(conf *PluginConf, ifName string) (*redirectInterfaceInfo, error) {
	prevResult, err := type100.GetResult(conf.PrevResult)
	if err != nil {
		return nil, fmt.Errorf("get prevResult: %w", err)
	}

	var iface *type100.Interface
	for _, i := range prevResult.Interfaces {
		if i.Name == ifName {
			iface = i
			break
		}
	}
	if iface == nil {
		return nil, fmt.Errorf("prevResult does not describe an interface named %q", ifName)
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("find interface %q: %w", ifName, err)
	}

	routeMTU, err := findRouteMTU(link)
	if err != nil {
		return nil, fmt.Errorf("resolve route MTU for %q: %w", ifName, err)
	}
	if routeMTU == 0 {
		// No route carries an explicit MTU metric — fall back to the link
		// MTU. This is the same fallback awslabs/tc-redirect-tap always
		// takes (it never reads route MTU at all); see the MTU caveat in
		// docs/vmtap-cni/configuration.md for when this fallback is wrong.
		routeMTU = iface.Mtu
	}

	return &redirectInterfaceInfo{
		name:     ifName,
		mac:      iface.Mac,
		mtu:      iface.Mtu,
		routeMTU: routeMTU,
	}, nil
}

// findRouteMTU returns the largest MTU metric set on any route bound to
// link, across both address families. Returns 0 if no route carries an
// explicit MTU (the common case when Cilium hasn't needed to shrink it for
// overlay/tunnel overhead).
func findRouteMTU(link netlink.Link) (int, error) {
	var maxMTU int
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteList(link, family)
		if err != nil {
			return 0, fmt.Errorf("list routes: %w", err)
		}
		for _, r := range routes {
			if r.MTU > maxMTU {
				maxMTU = r.MTU
			}
		}
	}
	return maxMTU, nil
}
