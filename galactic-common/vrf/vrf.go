package vrf

import (
	"fmt"
	"math"
	"slices"

	"github.com/datum-cloud/galactic-common/sysctl"
	"github.com/datum-cloud/galactic-common/util"
	"github.com/vishvananda/netlink"
)

const MinVRFId = uint32(1)
const MaxVRFId = uint32(math.MaxUint32 - 1)

func Add(vpc, vpcAttachment string) error {
	name := util.GenerateInterfaceNameVRF(vpc, vpcAttachment)

	vrfId, err := FindNextAvailableVRFId()
	if err != nil {
		return err
	}

	if err := Flush(vrfId); err != nil {
		return err
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: uint32(vrfId),
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

	vrfId, err := GetVRFIdForInterface(name)
	if err != nil {
		return err
	}

	if err := Flush(vrfId); err != nil {
		return err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	return netlink.LinkDel(link)
}

func Flush(vrfId uint32) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
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

func ListVRFLinks() ([]*netlink.Vrf, error) {
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

func FindNextAvailableVRFId() (uint32, error) {
	vrfs, err := ListVRFLinks()
	if err != nil {
		return 0, err
	}

	used := make([]uint32, 0, len(vrfs))
	for _, vrf := range vrfs {
		used = append(used, vrf.Table)
	}

	for vrfId := MinVRFId; vrfId <= MaxVRFId; vrfId++ {
		if !slices.Contains(used, vrfId) {
			return vrfId, nil
		}
	}

	return 0, fmt.Errorf("could not find any available VRF id")
}

func GetVRFIdForInterface(name string) (uint32, error) {
	vrfs, err := ListVRFLinks()
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

func GetVRFIdForVPC(vpc, vpcAttachment string) (uint32, error) {
	return GetVRFIdForInterface(util.GenerateInterfaceNameVRF(vpc, vpcAttachment))
}
