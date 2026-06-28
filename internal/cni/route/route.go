// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"fmt"
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

func Add(vpc, vpcAttachment string, prefix, nextHop, dev string) error {
	vrfID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return err
	}
	route, err := assembleRoute(vrfID, prefix, nextHop, dev)
	if err != nil {
		return err
	}
	return netlink.RouteAdd(route)
}

func Delete(vpc, vpcAttachment string, prefix, nextHop, dev string) error {
	vrfID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return err
	}
	route, err := assembleRoute(vrfID, prefix, nextHop, dev)
	if err != nil {
		return err
	}
	return netlink.RouteDel(route)
}
