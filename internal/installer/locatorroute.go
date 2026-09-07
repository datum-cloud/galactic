// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
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

// ensureLocatorLocalRoute installs a local route for this node's uSID locator
// /64, the Block and Node-ID prefix from its BGPRouter, into the kernel's local
// table pointed at loopback.
//
// A node has to be able to resolve a route to its own SIDs. Egress route
// registration resolves each SID once to pick the egress interface and next-hop
// MAC the datapath then redirects to, and for a same-node destination, an Envoy
// sidecar reaching a backend on its own node, that SID belongs to this node.
// Without a matching route the lookup fails against the locator's own discard
// route, registration fails, and same-node encapsulation is never set up.
//
// A route, deliberately, and not an address on a dummy interface. A locally
// assigned global address is published as a node address by cluster discovery,
// which lands it in every mesh peer's allowed addresses, and the mesh's own
// rules then steer traffic for it into a policy table where this datapath is
// not attached and could not parse the packets anyway, the tunnel having no
// Ethernet header for the first parse step. That silently blackholes every
// inter-node encapsulated packet. Discovery publishes addresses, not routes.
//
// Covering the whole /64 rather than individual SIDs is what makes this
// self-maintaining: every SID this node can compute shares that prefix, so no
// per-VPC bookkeeping is needed and a VPC nobody configured resolves like any
// other. It cannot shadow decapsulation either, since usid_ingress claims
// packets at tc ingress before any FIB lookup runs.
//
// Idempotent and safe to call repeatedly, so a BGPRouter that appears later, or
// a route flushed out from under it, is picked up without a restart.
//
// It also removes routes it installed for a locator this node no longer owns. A
// replace alone cannot: a changed Block or Node-ID is a different prefix, so the
// old route is left behind claiming address space this node gave up, and nothing
// would retract it.
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

	// Only after a successful install, and only with a valid desired prefix in
	// hand: pruning against the zero prefix would strip this node's working
	// route every time the BGPRouter is briefly unreadable during bring-up. A
	// prune failure is not an install failure, since same-node resolution
	// already works and a leftover only over-claims space.
	if err := pruneStaleLocatorLocalRoutes(lo.Attrs().Index, prefix); err != nil {
		slog.Warn("Could not remove stale uSID locator local routes; this node still "+
			"claims a locator prefix it no longer owns", "keep", prefix.String(), "err", err)
	}
	return nil
}

// pruneStaleLocatorLocalRoutes removes every locator local route on lo except
// keep. See staleLocatorLocalRoute for what it will and will not touch.
func pruneStaleLocatorLocalRoutes(loIndex int, keep netip.Prefix) error {
	routes, err := netlink.RouteListFiltered(unix.AF_INET6,
		&netlink.Route{Table: unix.RT_TABLE_LOCAL, LinkIndex: loIndex},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("list local table routes on lo: %w", err)
	}

	var errs []error
	for i := range routes {
		if !staleLocatorLocalRoute(routes[i], loIndex, keep) {
			continue
		}
		if err := netlink.RouteDel(&routes[i]); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", routes[i].Dst, err))
			continue
		}
		slog.Info("Removed stale uSID locator local route",
			"prefix", routes[i].Dst.String(), "keep", keep.String())
	}
	return errors.Join(errs...)
}

// staleLocatorLocalRoute reports whether r is one of this component's own
// routes for a prefix other than keep.
//
// The filtering carries the safety argument, the local table being mostly the
// kernel's and a wrong delete blackholing one of this node's own addresses.
// Every entry the kernel derives from an assigned address is a kernel-protocol
// /128 host route, and what this component installs is neither. So a candidate
// must be a local route on loopback, not kernel-derived, and exactly a /64, the
// one length ever written here. A loopback /128, ::1, and anything on another
// link all fail that.
func staleLocatorLocalRoute(r netlink.Route, loIndex int, keep netip.Prefix) bool {
	if r.LinkIndex != loIndex || r.Table != unix.RT_TABLE_LOCAL {
		return false
	}
	if r.Type != unix.RTN_LOCAL || r.Protocol == unix.RTPROT_KERNEL {
		return false
	}
	if r.Dst == nil || r.Dst.IP.To4() != nil {
		return false
	}
	ones, bits := r.Dst.Mask.Size()
	if bits != 128 || ones != uformat.BlockBits+uformat.NodeIDBits {
		return false
	}
	got, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok {
		return false
	}
	return netip.PrefixFrom(got.Unmap(), ones) != keep
}

// nodeLocatorPrefix returns the /64 carved out of this node's BGPRouter
// locator, or the zero Prefix when this node has no BGPRouter or that router
// carries no locator yet. Both are ordinary during bring-up and neither is an
// error. The router is matched on its target name, the same way every other
// component here finds a node's router.
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

// reconcileLocatorLocalRoute is Run's non-fatal wrapper: a missing BGPRouter or
// a transient API error must not stop the installer daemon, and the refresh
// ticker retries.
func reconcileLocatorLocalRoute(ctx context.Context, st ebpfDatapathState) {
	if err := ensureLocatorLocalRoute(ctx, st.k8sClient, st.namespace, st.nodeName); err != nil {
		slog.Warn("Could not install this node's uSID locator local route; "+
			"same-node SRv6 egress registration will fail until this succeeds", "err", err)
	}
}
