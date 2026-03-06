package routeegress

import (
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"github.com/datum-cloud/galactic-common/vrf"
)

const LoopbackDevice = "lo-galactic"

func Add(vpc, vpcAttachment string, prefix *net.IPNet, segments []net.IP) error {
	link, err := netlink.LinkByName(LoopbackDevice)
	if err != nil {
		return err
	}

	vrfId, err := vrf.GetVRFIdForVPC(vpc, vpcAttachment)
	if err != nil {
		return err
	}

	encap := &netlink.SEG6Encap{
		Mode:     nl.SEG6_IPTUN_MODE_ENCAP,
		Segments: segments,
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(vrfId),
		LinkIndex: link.Attrs().Index,
		Encap:     encap,
	}
	return netlink.RouteReplace(route)
}

func Delete(vpc, vpcAttachment string, prefix *net.IPNet, segments []net.IP) error {
	link, err := netlink.LinkByName(LoopbackDevice)
	if err != nil {
		return err
	}

	vrfId, err := vrf.GetVRFIdForVPC(vpc, vpcAttachment)
	if err != nil {
		return err
	}

	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(vrfId),
		LinkIndex: link.Attrs().Index,
	}
	return netlink.RouteDel(route)
}
