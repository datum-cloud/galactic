// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package neighborproxy

import (
	"net"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/pkg/common/util"
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
