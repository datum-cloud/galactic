// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/nldump"
)

// InPodPruneResult counts what PruneInPodEncapsulation removed.
type InPodPruneResult struct {
	// VethLinks counts the egress veth ends deleted. Deleting one end of a
	// pair deletes the other, which is then not counted again.
	VethLinks int
	// RedirectRoutes counts the main-table routes into a sidecar VRF.
	RedirectRoutes int
	// Seg6Routes counts the kernel seg6 routes in a sidecar VRF's table.
	Seg6Routes int
	// MapRows counts the sidecar-range rows removed from the shared maps.
	MapRows int
}

// Total is the number of objects removed.
func (r InPodPruneResult) Total() int {
	return r.VethLinks + r.RedirectRoutes + r.Seg6Routes + r.MapRows
}

// egressVethRegex matches the names egressVethNames gives a VRF's veth pair.
var egressVethRegex = regexp.MustCompile(`^iv[sp]([0-9]+)$`)

// PruneInPodEncapsulation removes the in-pod SRv6 encapsulation a sidecar
// with in-pod encapsulation left in the calling process's network namespace
// and in the node's shared pinned eBPF maps:
//
//   - the main-table routes into a VRF with a table in the sidecar's range,
//     except a host route to an address of that VRF (see redirectPrefixes)
//   - the kernel seg6 routes in such a VRF's table
//   - every veth named as egressVethNames names one for a table in the
//     sidecar's range
//   - every row in the sidecar's key range of vrf_table, ifindex_vrf_table,
//     egress_route_table and tp_iface_table (see sidecarmap.Prune), which a
//     sidecar without in-pod encapsulation never writes
//
// The VRFs themselves, their unreachable defaults and the routed link stay.
// Host rows of the maps are never touched. Every step is attempted even if an
// earlier one fails; the failures, including maps that cannot be opened, are
// joined. Repeating it removes nothing more.
func PruneInPodEncapsulation() (InPodPruneResult, error) {
	var (
		result InPodPruneResult
		errs   []error
	)
	links, err := nldump.LinkList()
	if err != nil {
		errs = append(errs, fmt.Errorf("list links: %w", err))
	}
	for _, l := range links {
		v, ok := l.(*netlink.Vrf)
		if !ok || v.Table < sidecarTableIDMin || v.Table > sidecarTableIDMax {
			continue
		}
		n, err := removeRedirectRoutes(v)
		result.RedirectRoutes += n
		if err != nil {
			errs = append(errs, err)
		}
		n, err = removeSeg6Routes(v.Table)
		result.Seg6Routes += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, l := range links {
		if !isEgressVeth(l) {
			continue
		}
		err := netlink.LinkDel(l)
		var nf netlink.LinkNotFoundError
		switch {
		case err == nil:
			result.VethLinks++
		case errors.Is(err, unix.ENODEV), errors.As(err, &nf):
			// Gone with its peer.
		default:
			errs = append(errs, fmt.Errorf("delete egress veth %s: %w", l.Attrs().Name, err))
		}
	}
	n, err := pruneDatapath(nil)
	result.MapRows = n
	if err != nil {
		errs = append(errs, fmt.Errorf("prune the sidecar's rows from the shared eBPF maps: %w", err))
	}
	return result, errors.Join(errs...)
}

// isEgressVeth reports whether l is a veth named as egressVethNames names
// the pair of a table in the sidecar's range.
func isEgressVeth(l netlink.Link) bool {
	if l.Type() != "veth" {
		return false
	}
	m := egressVethRegex.FindStringSubmatch(l.Attrs().Name)
	if m == nil {
		return false
	}
	table, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil || uint32(table) < sidecarTableIDMin || uint32(table) > sidecarTableIDMax {
		return false
	}
	inner, peer := egressVethNames(uint32(table))
	return l.Attrs().Name == inner || l.Attrs().Name == peer
}

// removeRedirectRoutes removes the main-table routes ensureRedirectRoute
// installed into v, recognised as redirectPrefixes recognises them, and
// returns how many it removed.
func removeRedirectRoutes(v *netlink.Vrf) (int, error) {
	local, err := vrfLocalAddresses(v.Index)
	if err != nil {
		return 0, err
	}
	prefixes, err := redirectPrefixes(v.Index, local)
	if err != nil {
		return 0, err
	}
	removed := 0
	var errs []error
	for _, p := range prefixes {
		err := netlink.RouteDel(&netlink.Route{Dst: p, Table: unix.RT_TABLE_MAIN, LinkIndex: v.Index})
		switch {
		case err == nil:
			removed++
		case errors.Is(err, unix.ESRCH), errors.Is(err, unix.ENOENT):
		default:
			errs = append(errs, fmt.Errorf("remove main-table redirect route %s via %s: %w", p, v.Name, err))
		}
	}
	return removed, errors.Join(errs...)
}

// removeSeg6Routes removes the kernel seg6 routes in table and returns how
// many it removed.
func removeSeg6Routes(table uint32) (int, error) {
	removed := 0
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := nldump.RouteListFiltered(family, &netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
		if err != nil {
			errs = append(errs, fmt.Errorf("list routes in table %d: %w", table, err))
			continue
		}
		for _, r := range routes {
			if _, ok := r.Encap.(*netlink.SEG6Encap); !ok || r.Dst == nil {
				continue
			}
			err := netlink.RouteDel(&r)
			switch {
			case err == nil:
				removed++
			case errors.Is(err, unix.ESRCH):
			default:
				errs = append(errs, fmt.Errorf("remove seg6 route %s from table %d: %w", r.Dst, table, err))
			}
		}
	}
	return removed, errors.Join(errs...)
}
