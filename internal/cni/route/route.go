// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/vrf"
)

func assembleRoute(vrfId uint32, prefix, nextHop, dev string) (*netlink.Route, error) {
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
			Table: int(vrfId),
		}, nil
	}

	link, err := netlink.LinkByName(dev)
	if err != nil {
		return nil, err
	}
	return &netlink.Route{
		Dst:       routeDst,
		Table:     int(vrfId),
		LinkIndex: link.Attrs().Index,
		Scope:     unix.RT_SCOPE_LINK,
	}, nil
}

func Add(vpc, vpcAttachment string, prefix, nextHop, dev string) error {
	vrfId, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return err
	}
	route, err := assembleRoute(vrfId, prefix, nextHop, dev)
	if err != nil {
		return err
	}
	return netlink.RouteAdd(route)
}

func Delete(vpc, vpcAttachment string, prefix, nextHop, dev string) error {
	vrfId, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		return err
	}
	route, err := assembleRoute(vrfId, prefix, nextHop, dev)
	if err != nil {
		return err
	}
	return netlink.RouteDel(route)
}
