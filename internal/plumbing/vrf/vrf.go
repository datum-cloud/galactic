// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vrf manages the Linux VRF interfaces that isolate Galactic VPC
// networks. Each VPC gets one VRF with its own routing table ID per node,
// shared by every attachment landing on that VPC on that node rather than one
// per attachment. Requires CAP_NET_ADMIN.
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

// ErrNotFound is wrapped by TableID when no VRF interface for that VPC exists
// in this process's own network namespace.
//
// Callers need that distinguishable from a genuine netlink failure, because
// absent is an ordinary condition for some of them: a process in the host's
// root namespace legitimately cannot see a VRF the ingress sidecar created
// inside a pod's namespace, while a failed link listing is a real problem
// either way.
var ErrNotFound = errors.New("vrf: no VRF interface for this VPC in this network namespace")

// vrfMu serializes VRF creation and deletion within one process. It does not by
// itself protect two separate CNI invocations racing on the same node, each
// being its own process, so Add and Delete also take a cross-process lock.
var vrfMu sync.Mutex

// Add creates the Linux VRF interface for a base62-encoded VPC, allocating the
// next available routing table ID and applying the required sysctls.
//
// The VRF is shared by every attachment on this VPC on this node, so concurrent
// calls, from goroutines here or from separate plugin processes attaching
// different pods, are serialized. It is idempotent by name: a VRF that already
// exists, whether created by a sibling attachment or left behind by a failed
// ADD, returns nil.
func Add(vpc string) error {
	vrfMu.Lock()
	defer vrfMu.Unlock()

	lock, err := acquireLock()
	if err != nil {
		return err
	}
	defer func() { _ = lock.close() }()

	name := intf.GenerateInterfaceNameVRF(vpc)

	if _, err := netlink.LinkByName(name); err == nil {
		return nil
	}

	vrfID, err := findNextAvailableVRFID()
	if err != nil {
		return err
	}

	if err := FlushTable(vrfID); err != nil {
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

// Delete flushes every route from the VRF's routing table and removes the
// interface for a base62-encoded VPC. Idempotent: an absent interface returns
// nil.
//
// Callers must only invoke it once no attachment on this VPC on this node
// remains live, since deleting out from under a sibling breaks it. The CNI
// teardown path never calls it for that reason; only garbage collection does,
// after confirming through every advertisement for this VPC and node that none
// is still in use.
func Delete(vpc string) error {
	vrfMu.Lock()
	defer vrfMu.Unlock()

	lock, err := acquireLock()
	if err != nil {
		return err
	}
	defer func() { _ = lock.close() }()

	name := intf.GenerateInterfaceNameVRF(vpc)

	vrfID, err := getVRFIDForInterface(name)
	if err != nil {
		return nil // VRF already gone — idempotent
	}

	if err := FlushTable(vrfID); err != nil {
		return err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // interface already gone — idempotent
	}

	return netlink.LinkDel(link)
}

// TableID returns the Linux routing table ID for a base62-encoded VPC's VRF.
// The error wraps ErrNotFound when no such interface exists in this process's
// own network namespace, which some callers treat as ordinary rather than a
// failure.
func TableID(vpc string) (uint32, error) {
	return getVRFIDForInterface(intf.GenerateInterfaceNameVRF(vpc))
}

// Exists reports whether a VRF interface for the given VPC exists in the
// kernel.
func Exists(vpc string) error {
	name := intf.GenerateInterfaceNameVRF(vpc)
	if _, err := netlink.LinkByName(name); err != nil {
		return fmt.Errorf("VRF interface %q not found", name)
	}
	return nil
}

// FlushTable removes every IPv4 and IPv6 route from the given routing table.
// Add calls it before creating a VRF on a reused table ID, which happens when a
// previous VRF was removed without going through Delete, and Delete calls it
// before removing the interface, so a stale table is always cleared rather than
// inherited.
//
// Exported so garbage collection's fallback path, which removes a legacy-named
// interface directly rather than through Delete, can flush the table itself and
// get the same guarantee.
func FlushTable(vrfID uint32) error {
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

// ListVRFLinks returns all VRF interfaces currently present on the host.
func ListVRFLinks() ([]*netlink.Vrf, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	vrfLinks := make([]*netlink.Vrf, 0, len(links))
	for _, link := range links {
		if v, ok := link.(*netlink.Vrf); ok {
			vrfLinks = append(vrfLinks, v)
		}
	}
	return vrfLinks, nil
}

func listVRFLinks() ([]*netlink.Vrf, error) {
	return ListVRFLinks()
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
	return 0, fmt.Errorf("could not find VRF ID for interface %s: %w", name, ErrNotFound)
}
