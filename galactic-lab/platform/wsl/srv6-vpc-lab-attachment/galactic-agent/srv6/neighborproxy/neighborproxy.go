package neighborproxy

import (
	"net"

	"github.com/vishvananda/netlink"

	"github.com/datum-cloud/galactic-common/util"
)

func Add(ipnet *net.IPNet, vpc, vpcAttachment string) error {
	dev := util.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}

	neigh := &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		IP:        ipnet.IP,
		State:     netlink.NUD_PERMANENT,
		Flags:     netlink.NTF_PROXY,
	}

	return netlink.NeighAdd(neigh)
}

func Delete(ipnet *net.IPNet, vpc, vpcAttachment string) error {
	dev := util.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}

	neigh := &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		IP:        ipnet.IP,
		State:     netlink.NUD_PERMANENT,
		Flags:     netlink.NTF_PROXY,
	}

	return netlink.NeighDel(neigh)
}
