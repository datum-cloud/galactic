// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vrf

import (
	"fmt"
	"math"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
	"go.datum.net/galactic/pkg/common/sysctl"
	"go.datum.net/galactic/pkg/common/util"
)

const minVRFId = uint32(1)
const maxVRFId = uint32(math.MaxUint32 - 1)

func Add(vpc, vpcAttachment string) error {
	name := util.GenerateInterfaceNameVRF(vpc, vpcAttachment)

	vrfId, err := findNextAvailableVRFId()
	if err != nil {
		return err
	}

	if err := flush(vrfId); err != nil {
		return err
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: vrfId,
	}

	if err := netlink.LinkAdd(vrf); err != nil {
		return err
	}

	if err := sysctl.ConfigureInterfaceSysctls(name); err != nil {
		return err
	}

	return netlink.LinkSetUp(vrf)
}

func Delete(vpc, vpcAttachment string) error {
	name := util.GenerateInterfaceNameVRF(vpc, vpcAttachment)

	vrfId, err := getVRFIdForInterface(name)
	if err != nil {
		return err
	}

	if err := flush(vrfId); err != nil {
		return err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	return netlink.LinkDel(link)
}

func GetVRFIdForVPC(vpc, vpcAttachment string) (uint32, error) {
	return getVRFIdForInterface(util.GenerateInterfaceNameVRF(vpc, vpcAttachment))
}

func flush(vrfId uint32) error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: int(vrfId)},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return err
		}
		for _, route := range routes {
			if err := netlink.RouteDel(&route); err != nil {
				return err
			}
		}
	}
	return nil
}

func listVRFLinks() ([]*netlink.Vrf, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	vrfLinks := make([]*netlink.Vrf, 0, len(links))
	for _, link := range links {
		if vrf, ok := link.(*netlink.Vrf); ok {
			vrfLinks = append(vrfLinks, vrf)
		}
	}
	return vrfLinks, nil
}

func findNextAvailableVRFId() (uint32, error) {
	vrfs, err := listVRFLinks()
	if err != nil {
		return 0, err
	}

	used := make([]uint32, 0, len(vrfs))
	for _, vrf := range vrfs {
		used = append(used, vrf.Table)
	}

	for vrfId := minVRFId; vrfId <= maxVRFId; vrfId++ {
		if !slices.Contains(used, vrfId) {
			return vrfId, nil
		}
	}

	return 0, fmt.Errorf("could not find any available VRF id")
}

func getVRFIdForInterface(name string) (uint32, error) {
	vrfs, err := listVRFLinks()
	if err != nil {
		return 0, err
	}

	for _, vrf := range vrfs {
		if vrf.Name == name {
			return vrf.Table, nil
		}
	}
	return 0, fmt.Errorf("could not find VRF ID for interface: %s", name)
}
