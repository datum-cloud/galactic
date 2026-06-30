// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vrf manages Linux VRF interfaces for Galactic VPC network isolation.
// Each VPC attachment gets its own VRF with a unique routing table ID.
// Requires CAP_NET_ADMIN.
package vrf

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

const minVRFID = uint32(1)
const maxVRFID = uint32(math.MaxUint32 - 1)

// vrfMu serializes VRF creation to prevent two concurrent CNI ADD calls from
// scanning the same free table ID and both attempting to create a VRF with it.
var vrfMu sync.Mutex

// Add creates a Linux VRF interface for the given base62-encoded VPC and
// VPCAttachment, allocating the next available routing table ID and applying
// the required sysctl settings. Concurrent calls are serialized internally.
// If a VRF with the same name already exists (e.g. left behind by a previous
// failed cmdAdd with no corresponding cmdDel), Add returns nil.
func Add(vpc, vpcAttachment string) error {
	vrfMu.Lock()
	defer vrfMu.Unlock()

	name := intf.GenerateInterfaceNameVRF(vpc, vpcAttachment)

	if _, err := netlink.LinkByName(name); err == nil {
		return nil
	}

	vrfID, err := findNextAvailableVRFID()
	if err != nil {
		return err
	}

	if err := flush(vrfID); err != nil {
		return err
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Table: vrfID,
	}

	if err := netlink.LinkAdd(vrf); err != nil {
		return err
	}

	if err := sysctl.ConfigureInterfaceSysctls(name); err != nil {
		return err
	}

	return netlink.LinkSetUp(vrf)
}

// Delete flushes all routes from the VRF routing table and removes the VRF
// interface for the given base62-encoded VPC and VPCAttachment.
func Delete(vpc, vpcAttachment string) error {
	name := intf.GenerateInterfaceNameVRF(vpc, vpcAttachment)

	vrfID, err := getVRFIDForInterface(name)
	if err != nil {
		return err
	}

	if err := flush(vrfID); err != nil {
		return err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	return netlink.LinkDel(link)
}

// TableID returns the Linux routing table ID for the VRF associated with the
// given base62-encoded VPC and VPCAttachment.
func TableID(vpc, vpcAttachment string) (uint32, error) {
	return getVRFIDForInterface(intf.GenerateInterfaceNameVRF(vpc, vpcAttachment))
}

func flush(vrfID uint32) error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: int(vrfID)},
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

func findNextAvailableVRFID() (uint32, error) {
	vrfs, err := listVRFLinks()
	if err != nil {
		return 0, err
	}

	used := make(map[uint32]struct{}, len(vrfs))
	for _, vrf := range vrfs {
		used[vrf.Table] = struct{}{}
	}

	for vrfID := minVRFID; vrfID <= maxVRFID; vrfID++ {
		if _, ok := used[vrfID]; !ok {
			return vrfID, nil
		}
	}

	return 0, errors.New("could not find any available VRF id")
}

func getVRFIDForInterface(name string) (uint32, error) {
	vrfs, err := listVRFLinks()
	if err != nil {
		return 0, err
	}

	vrfByName := make(map[string]*netlink.Vrf, len(vrfs))
	for _, vrf := range vrfs {
		vrfByName[vrf.Name] = vrf
	}

	if vrf, ok := vrfByName[name]; ok {
		return vrf.Table, nil
	}
	return 0, fmt.Errorf("could not find VRF ID for interface: %s", name)
}
