// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/vrf"
)

func assembleRoute(vrfID uint32, prefix, nextHop, dev string) (*netlink.Route, error) {
	_, routeDst, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, err
	}

	if nextHop != "" {
		routeGw := net.ParseIP(nextHop)
		if routeGw == nil {
			return nil, fmt.Errorf("cannot parse gateway IP: %s", nextHop)
		}
		return &netlink.Route{
			Dst:   routeDst,
			Gw:    routeGw,
			Table: int(vrfID),
		}, nil
	}

	link, err := netlink.LinkByName(dev)
	if err != nil {
		return nil, err
	}
	return &netlink.Route{
		Dst:       routeDst,
		Table:     int(vrfID),
		LinkIndex: link.Attrs().Index,
		Scope:     unix.RT_SCOPE_LINK,
	}, nil
}

// Add installs the termination route for prefix into vpc's VRF table and
// reports whether it created the route. It is idempotent: if an identical
// route is already present it returns (false, nil) rather than an error.
//
// The VRF route table is shared by every attachment (and pod) in a VPC on a
// node, so the same prefix can validly be installed more than once. created
// tells the caller whether this call inserted the route, so it can avoid
// recording a route that predated it — rolling back a shared pre-existing
// route would remove one another pod or attachment depends on.
func Add(vpc, prefix, nextHop, dev string) (created bool, err error) {
	vrfID, err := vrf.TableID(vpc)
	if err != nil {
		return false, err
	}
	route, err := assembleRoute(vrfID, prefix, nextHop, dev)
	if err != nil {
		return false, err
	}
	if err := netlink.RouteAdd(route); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, err
	}
	slog.Debug("route: termination route added", "prefix", prefix, "via", nextHop, "dev", dev, "vrfTable", vrfID)
	return true, nil
}

func Delete(vpc, prefix, nextHop, dev string) error {
	vrfID, err := vrf.TableID(vpc)
	if err != nil {
		return err
	}
	route, err := assembleRoute(vrfID, prefix, nextHop, dev)
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(route); err != nil {
		return err
	}
	slog.Debug("route: termination route deleted", "prefix", prefix, "via", nextHop, "dev", dev, "vrfTable", vrfID)
	return nil
}
