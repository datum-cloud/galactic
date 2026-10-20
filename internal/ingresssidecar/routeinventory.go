// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// listRoutes returns the egress routes this pod installed in tableID, for the
// startup inventory.
//
// EnsureRoute writes two things per route: an egress_route_table entry, in a
// map every sidecar pod on the node shares, and a redirect route in this pod's
// own main table, out the VRF device for tableID. The map entry cannot show
// which pod wrote it: its key holds only a table ID, which each pod allocates
// from the same range, so a sibling pod overlapping this one on the node can
// hold entries under the same ID. The redirect route lives in this pod's
// network namespace, which no other pod writes. So a route counts as this
// pod's when its redirect route exists, and the map supplies its SID when it
// still has the entry.
//
// A map entry with no redirect route is not this pod's to judge: it may be a
// sibling's, or one of this pod's whose redirect route was lost. It is left in
// place and logged, never inventoried, since tearing it down could break a
// live sibling. A seg6 route in tableID itself, which releases before
// egress_route_table installed, is still this pod's and is inventoried too.
//
// The proof covers the route, not the map entry: a sibling holding the same
// table ID and prefix shares the entry, and this pod then reads, and on
// teardown removes, that shared entry. Ordinary teardown does the same, so
// the inventory adds no new case.
func listRoutes(tableID uint32) ([]RouteInfo, error) {
	link, err := vrfLinkForTable(tableID)
	if err != nil {
		return nil, err
	}
	local, err := vrfLocalAddresses(link.Attrs().Index)
	if err != nil {
		return nil, err
	}
	redirects, err := redirectPrefixes(link.Attrs().Index, local)
	if err != nil {
		return nil, err
	}
	legacy, err := legacySeg6Routes(tableID)
	if err != nil {
		return nil, err
	}

	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(ebpfPinDir)
	if err != nil {
		return nil, fmt.Errorf("open pinned egress_route_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	byTable, err := table.Prefixes()
	if err != nil {
		return nil, err
	}

	routes, unowned, err := mergeRouteInventory(redirects, legacy, byTable[tableID],
		func(prefix *net.IPNet) (net.IP, bool, error) { return table.Lookup(tableID, prefix) })
	if err != nil {
		return nil, err
	}
	if len(unowned) > 0 {
		slog.Warn("ingresssidecar: egress_route_table holds entries for a VRF table this pod has no "+
			"redirect route for; left in place, since another sidecar pod on this node may own them",
			"table", tableID, "entries", len(unowned))
		slog.Debug("ingresssidecar: egress_route_table entries left in place", "table", tableID, "prefixes", unowned)
	}
	return routes, nil
}

// mergeRouteInventory builds the inventory for one VRF table from this pod's
// redirect prefixes, its legacy seg6 routes, and the prefixes
// egress_route_table holds for the table, using sidFor to read an entry's
// SID. It returns the routes this pod owns and the map prefixes it does not.
//
// A redirect prefix whose map entry is gone is still returned, with a nil
// SID: the route is this pod's and still needs tearing down if unclaimed.
func mergeRouteInventory(
	redirects []*net.IPNet, legacy []RouteInfo, mapPrefixes map[string]struct{},
	sidFor func(*net.IPNet) (net.IP, bool, error),
) (routes []RouteInfo, unowned []string, err error) {
	owned := make(map[string]struct{}, len(redirects)+len(legacy))
	for _, prefix := range redirects {
		key := prefix.String()
		if _, dup := owned[key]; dup {
			continue
		}
		owned[key] = struct{}{}
		var sid net.IP
		if _, ok := mapPrefixes[key]; ok {
			got, found, lerr := sidFor(prefix)
			if lerr != nil {
				return nil, nil, lerr
			}
			if found {
				sid = got
			}
		}
		routes = append(routes, RouteInfo{Prefix: prefix, SID: sid})
	}
	for _, r := range legacy {
		key := r.Prefix.String()
		if _, dup := owned[key]; dup {
			continue
		}
		owned[key] = struct{}{}
		routes = append(routes, r)
	}
	for key := range mapPrefixes {
		if _, ok := owned[key]; !ok {
			unowned = append(unowned, key)
		}
	}
	return routes, unowned, nil
}

// redirectPrefixes returns the destination of every route in this pod's main
// table that leaves through linkIndex, the VRF device ensureRedirectRoute
// points them at, except a host route to an address in local.
//
// ensureGatewayVRFRoute also routes into the VRF device, for the VPC's own
// gateway address, and no EndpointSlice claims that route. A backend redirect
// always targets a remote address, never one this VRF holds, since
// DeriveGatewayAddress draws gateway addresses from a prefix disjoint from
// tenant address space.
func redirectPrefixes(linkIndex int, local map[string]struct{}) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(family,
			&netlink.Route{Table: unix.RT_TABLE_MAIN, LinkIndex: linkIndex},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
		if err != nil {
			return nil, fmt.Errorf("list main-table redirect routes via ifindex %d: %w", linkIndex, err)
		}
		for _, r := range routes {
			if r.Dst == nil {
				continue
			}
			if ones, bits := r.Dst.Mask.Size(); ones == bits {
				if _, ok := local[r.Dst.IP.String()]; ok {
					continue // the gateway return route, not a backend redirect
				}
			}
			out = append(out, r.Dst)
		}
	}
	return out, nil
}

// vrfLocalAddresses returns every address assigned to an interface enslaved
// to the VRF device at vrfIndex.
func vrfLocalAddresses(vrfIndex int) (map[string]struct{}, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	local := make(map[string]struct{})
	for _, link := range links {
		if link.Attrs().MasterIndex != vrfIndex {
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if errors.Is(err, unix.ENODEV) {
			continue // removed since LinkList, so it holds no address
		}
		if err != nil {
			return nil, fmt.Errorf("list addresses on %s: %w", link.Attrs().Name, err)
		}
		for _, a := range addrs {
			local[a.IP.String()] = struct{}{}
		}
	}
	return local, nil
}

// legacySeg6Routes returns the kernel seg6-encapsulated routes in tableID,
// which releases before egress_route_table installed instead of a map entry.
func legacySeg6Routes(tableID uint32) ([]RouteInfo, error) {
	var infos []RouteInfo
	// Two passes, not AF_UNSPEC, matching internal/plumbing/vrf.FlushTable's
	// own approach to listing everything in one table across both families.
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: int(tableID)},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return nil, fmt.Errorf("list routes in table %d: %w", tableID, err)
		}
		for _, route := range routes {
			enc, ok := route.Encap.(*netlink.SEG6Encap)
			if !ok || len(enc.Segments) == 0 || route.Dst == nil {
				continue // not a seg6 egress route
			}
			infos = append(infos, RouteInfo{Prefix: route.Dst, SID: enc.Segments[0]})
		}
	}
	return infos, nil
}
