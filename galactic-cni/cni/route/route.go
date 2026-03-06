package route

import (
	"net"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"

	gutil "github.com/datum-cloud/galactic-common/util"
	"github.com/datum-cloud/galactic-common/vrf"
)

func assembleRoute(vrfId uint32, prefix, nextHop, dev string) (*netlink.Route, error) {
	_, routeDst, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, err
	}

	if nextHop != "" {
		routeGw, err := gutil.ParseIP(nextHop)
		if err != nil {
			return nil, err
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
	vrfId, err := vrf.GetVRFIdForVPC(vpc, vpcAttachment)
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
	vrfId, err := vrf.GetVRFIdForVPC(vpc, vpcAttachment)
	if err != nil {
		return err
	}
	route, err := assembleRoute(vrfId, prefix, nextHop, dev)
	if err != nil {
		return err
	}
	return netlink.RouteDel(route)
}
