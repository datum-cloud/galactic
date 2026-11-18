// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nodelocator derives a node's SRv6 uSID locator from its BGPRouter,
// the single trusted source of a node's physical locator.
package nodelocator

import (
	"context"
	"fmt"
	"net/netip"

	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// Prefix returns the /64 carved out of a node's BGPRouter
// locator, or the zero Prefix when the node has no BGPRouter or that router
// carries no locator yet. Both are ordinary during bring-up and neither is an
// error. The router is the Galactic-owned one (no routerClassName) matched on
// its target name, the same way every Galactic component finds a node's
// router; more than one is an error rather than an arbitrary pick.
func Prefix(
	ctx context.Context, k8s client.Reader, namespace, nodeName string,
) (netip.Prefix, error) {
	routers := &bgpv1alpha1.BGPRouterList{}
	if err := k8s.List(ctx, routers, client.InNamespace(namespace)); err != nil {
		return netip.Prefix{}, fmt.Errorf("list BGPRouters in namespace %s: %w", namespace, err)
	}

	var mine []bgpv1alpha1.BGPRouter
	for _, r := range bgpv1alpha1.LegacyOwnedRouters(routers.Items) {
		if r.Spec.TargetRef.Name == nodeName {
			mine = append(mine, r)
		}
	}
	if len(mine) > 1 {
		return netip.Prefix{}, fmt.Errorf("ambiguous BGP config: %d BGPRouters target node %s in namespace %s",
			len(mine), nodeName, namespace)
	}
	if len(mine) == 0 {
		return netip.Prefix{}, nil
	}
	r := mine[0]
	if r.Spec.SRv6Locator == "" || r.Spec.NodeID == 0 {
		return netip.Prefix{}, nil
	}
	locator, err := netip.ParsePrefix(r.Spec.SRv6Locator)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse SRv6 locator %q: %w", r.Spec.SRv6Locator, err)
	}
	if !locator.Addr().Is6() || locator.Bits() != uformat.BlockBits {
		return netip.Prefix{}, fmt.Errorf(
			"SRv6 locator %q must be an IPv6 /%d uSID Block", r.Spec.SRv6Locator, uformat.BlockBits)
	}
	if r.Spec.NodeID < uformat.NodeIDMin || r.Spec.NodeID > uformat.NodeIDMax {
		return netip.Prefix{}, fmt.Errorf("BGPRouter %s: nodeID %d outside [%#x,%#x]",
			r.Name, r.Spec.NodeID, uint16(uformat.NodeIDMin), uint16(uformat.NodeIDMax))
	}

	// Node-ID occupies bits 49-64, immediately after the 48-bit Block --
	// the same layout uformat.Block/NodeID read back out of a SID.
	b := locator.Addr().As16()
	b[6] = byte(uint16(r.Spec.NodeID) >> 8)
	b[7] = byte(uint16(r.Spec.NodeID))
	return netip.PrefixFrom(netip.AddrFrom16(b), uformat.BlockBits+uformat.NodeIDBits), nil
}
