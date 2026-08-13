// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vrf manages Linux VRF interfaces for Galactic VPC network isolation.
// Each VPC gets its own VRF with a unique routing table ID, per node — shared
// by every attachment (pod or VM) landing on that VPC on that node, not
// per-attachment. Requires CAP_NET_ADMIN.
package vrf

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

const minVRFID = uint32(1)
const maxVRFID = uint32(math.MaxUint32 - 1)

// vrfMu serializes VRF creation/deletion within a single process (e.g.
// concurrent goroutines in galactic-router's GC). It does not, by itself,
// protect against two separate CNI ADD/DEL invocations racing on the same
// node — each is its own OS process — so Add and Delete also take the
// cross-process flock in lock.go.
var vrfMu sync.Mutex

// Add creates a Linux VRF interface for the given base62-encoded VPC,
// allocating the next available routing table ID and applying the required
// sysctl settings. The VRF is shared by every attachment (pod or VM) on this
// VPC on this node: concurrent calls — whether from goroutines in this
// process, from separate CNI plugin processes attaching different pods to
// the same VPC, or both — are serialized, and Add is idempotent by name. If
// a VRF with the same name already exists (because another attachment on
// this VPC already created it, or one was left behind by a previous failed
// cmdAdd with no corresponding cmdDel), Add returns nil.
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
// interface for the given base62-encoded VPC. Delete is idempotent: if the
// VRF interface does not exist, it returns nil. Callers must only invoke
// Delete once no attachment on this VPC on this node remains live — deleting
// out from under a still-live sibling attachment breaks it. galactic-veth's
// own cmdDel never calls this directly for exactly that reason; only
// galactic-router's GC controller does, after confirming via every
// BGPAdvertisement for this VPC/node that none are still in use.
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

	if err := flush(vrfID); err != nil {
		return err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // interface already gone — idempotent
	}

	return netlink.LinkDel(link)
}

// TableID returns the Linux routing table ID for the VRF associated with the
// given base62-encoded VPC.
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

// vrfNameRegex matches the deterministic VRF interface name pattern this
// package's own Add generates ("G%09sV" — see intf.GenerateInterfaceNameVRF)
// — one VRF per VPC, shared across every attachment on that VPC on this
// node. Base62 includes digits and letters. Mirrors internal/gc/gc.go's
// identical, older regex (kept separate rather than shared: this is a new,
// narrower need — reading a VPC back out of a name, not the GC sweep's own
// orphan-detection bookkeeping — datum-cloud/enhancements#865).
var vrfNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})V$`)

// legacyVRFNameRegex matches the VRF interface name this package generated
// before the VRF became per-VPC: the template was "G%09s%03sV", carrying a
// VPCAttachment segment the current per-VPC name no longer does. A node
// upgraded in place keeps whatever VRFs it created under the old template
// — see internal/gc/gc.go's identical regex for the fuller history.
var legacyVRFNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})[A-Za-z0-9]{3}V$`)

// ResolveVPC extracts the base62-encoded VPC a Galactic-managed VRF
// interface belongs to, accepting both the current per-VPC name and the
// legacy pre-rename name — both resolve to the same VPC, since only the
// leading base62 segment ever encodes it. Returns ok=false for a name that
// doesn't match either Galactic VRF shape at all (e.g. a non-Galactic VRF
// interface on the same host).
func ResolveVPC(name string) (vpc string, ok bool) {
	if matches := vrfNameRegex.FindStringSubmatch(name); matches != nil {
		return strings.TrimLeft(matches[1], "0"), true
	}
	if matches := legacyVRFNameRegex.FindStringSubmatch(name); matches != nil {
		return strings.TrimLeft(matches[1], "0"), true
	}
	return "", false
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
	return 0, fmt.Errorf("could not find VRF ID for interface: %s", name)
}
