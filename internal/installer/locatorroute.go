// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ensureLocatorLocalRoute installs a local route for this node's own uSID
// locator /64 -- the Block(48) + Node-ID(16) prefix from its BGPRouter --
// into the kernel's local table, pointed at lo.
//
// This exists because a node has to be able to resolve a route to its *own*
// SIDs. internal/plumbing/ebpf/egressroutemap's resolveLinkAndL2 calls
// netlink.RouteGet(sid) once per registration to pick the egress interface
// and next-hop MAC that usid_egress will then redirect to, and for a
// same-node destination (an Envoy sidecar reaching a backend on its own
// node) that SID belongs to this very node. Without a matching route,
// RouteGet fails against the locator's own Null0 discard route with EINVAL,
// registration fails, and same-node SRv6 encapsulation is never set up.
//
// A route, deliberately, and not an address on a dummy interface -- which is
// how this was previously satisfied. A locally-assigned global address is
// published as a node address by cluster discovery, which lands it in every
// KubeSpan peer's allowedIPs; KubeSpan's nftables chains then steer traffic
// to it into the WireGuard policy table, where this datapath is not attached
// (attach.ResolveInterfaces skips wireguard links) and could not parse it
// anyway, a WireGuard interface being link-type RAW with no Ethernet header
// for usid_ingress's first parse step. That silently blackholed every
// inter-node SRv6 packet. Cluster discovery publishes addresses, not routes,
// so a local route restores resolution without re-creating that.
//
// Covering the whole /64 rather than individual SIDs is what makes this
// self-maintaining: every SID this node can compute shares that prefix, so
// no per-VPC or per-Argument bookkeeping is needed, and a VPC whose Argument
// nobody thought to configure resolves the same as any other. It cannot
// shadow decapsulation either, because usid_ingress claims packets at tc
// ingress before any FIB lookup runs.
//
// Idempotent (RouteReplace), and safe to call repeatedly: Run invokes it at
// startup and on its refresh ticker, so a BGPRouter that appears later, or a
// route flushed out from under us, is picked up without a restart.
func ensureLocatorLocalRoute(ctx context.Context, k8s client.Client, namespace, nodeName string) error {
	if k8s == nil || nodeName == "" {
		return nil // no node identity configured; nothing to resolve against
	}

	prefix, err := nodeLocatorPrefix(ctx, k8s, namespace, nodeName)
	if err != nil {
		return err
	}
	if !prefix.IsValid() {
		return nil // this node's BGPRouter carries no SRv6 locator yet
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("look up lo: %w", err)
	}

	route := &netlink.Route{
		Dst:       &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), 128)},
		LinkIndex: lo.Attrs().Index,
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
		Scope:     netlink.SCOPE_HOST,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("install local route %s dev lo table local: %w", prefix, err)
	}
	return nil
}

// nodeLocatorPrefix returns the Block(48)+Node-ID(16) /64 carved out of this
// node's BGPRouter locator, or the zero Prefix when this node has no
// BGPRouter or that router carries no SRv6 locator yet -- both ordinary
// during bring-up, and neither an error.
//
// Matched on Spec.TargetRef.Name, the same way internal/cnibgp and
// internal/ingresssidecar both find the router for a node.
func nodeLocatorPrefix(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (netip.Prefix, error) {
	routers := &bgpv1alpha1.BGPRouterList{}
	if err := k8s.List(ctx, routers, client.InNamespace(namespace)); err != nil {
		return netip.Prefix{}, fmt.Errorf("list BGPRouters in namespace %s: %w", namespace, err)
	}

	for _, r := range routers.Items {
		if r.Spec.TargetRef.Name != nodeName {
			continue
		}
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
	return netip.Prefix{}, nil
}

// reconcileLocatorLocalRoute is Run's non-fatal wrapper: a missing or
// not-yet-created BGPRouter, or a transient API error, must not stop the
// installer daemon, and the refresh ticker retries on its own.
func reconcileLocatorLocalRoute(ctx context.Context, st ebpfDatapathState) {
	if err := ensureLocatorLocalRoute(ctx, st.k8sClient, st.namespace, st.nodeName); err != nil {
		slog.Warn("Could not install this node's uSID locator local route; "+
			"same-node SRv6 egress registration will fail until this succeeds", "err", err)
	}
}
