// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// Backend is the kernel-facing interface Store converges VRF and SRv6
// egress-route state against. kernelBackend (below) wires it to
// internal/plumbing/vrf and internal/plumbing/srv6 directly — the same
// primitives galactic-cni's own pod-attachment path uses; see §2 of the
// plan for why this is "not new kernel-programming work." Tests use a fake.
type Backend interface {
	// EnsureVRF creates (idempotently) the per-VPC Linux VRF device and
	// returns its kernel routing table ID.
	EnsureVRF(vpc string) (tableID uint32, err error)
	// RemoveVRF tears down the per-VPC VRF device. Callers must only call
	// this once no route for this VPC remains live or in its own grace
	// period — see vrf.Delete's own doc comment on why deleting out from
	// under a still-live sibling breaks it.
	RemoveVRF(vpc string) error
	// EnsureRoute installs (idempotently — see srv6.RouteEgressAdd's use of
	// netlink.RouteReplace) the seg6 ENCAP_RED route for prefix, toward
	// sid, in tableID.
	EnsureRoute(prefix *net.IPNet, sid net.IP, tableID uint32) error
	// RemoveRoute removes the route EnsureRoute installed.
	RemoveRoute(prefix *net.IPNet, tableID uint32) error
	// ListVRFs returns every Galactic per-VPC VRF device currently present
	// on the host, resolved back to its owning VPC — the startup-inventory
	// step (§9 item 2 of the plan; see Store.Inventory).
	ListVRFs() ([]VRFInfo, error)
	// ListRoutes returns every seg6-encapsulated route currently installed
	// in tableID — the route half of the same startup-inventory step.
	ListRoutes(tableID uint32) ([]RouteInfo, error)
}

// VRFInfo describes one kernel VRF device discovered by Backend.ListVRFs.
type VRFInfo struct {
	VPC     string
	TableID uint32
}

// RouteInfo describes one seg6 egress route discovered by
// Backend.ListRoutes.
type RouteInfo struct {
	Prefix *net.IPNet
	SID    net.IP
}

// kernelBackend is the production Backend.
type kernelBackend struct{}

// NewKernelBackend returns the production Backend, wired to real kernel
// state via internal/plumbing/vrf and internal/plumbing/srv6. Requires
// CAP_NET_ADMIN — see §6 of the plan.
func NewKernelBackend() Backend { return kernelBackend{} }

func (kernelBackend) EnsureVRF(vpc string) (uint32, error) {
	if err := vrf.Add(vpc); err != nil {
		return 0, fmt.Errorf("create VRF for vpc %s: %w", vpc, err)
	}
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		return 0, fmt.Errorf("resolve VRF table ID for vpc %s: %w", vpc, err)
	}
	return tableID, nil
}

func (kernelBackend) RemoveVRF(vpc string) error {
	if err := vrf.Delete(vpc); err != nil {
		return fmt.Errorf("delete VRF for vpc %s: %w", vpc, err)
	}
	return nil
}

func (kernelBackend) EnsureRoute(prefix *net.IPNet, sid net.IP, tableID uint32) error {
	if err := srv6.RouteEgressAdd(prefix, sid, tableID); err != nil {
		return fmt.Errorf("install seg6 route for %s: %w", prefix, err)
	}
	return nil
}

func (kernelBackend) RemoveRoute(prefix *net.IPNet, tableID uint32) error {
	if err := srv6.RouteEgressDel(prefix, tableID); err != nil {
		return fmt.Errorf("remove seg6 route for %s: %w", prefix, err)
	}
	return nil
}

// vrfNameRegex matches the interface name intf.GenerateInterfaceNameVRF
// produces for a VPC ("G%09sV" — 'G', 9 zero-padded base62 characters,
// 'V'). Mirrors internal/gc's identically-purposed, unexported
// vrfNameRegex; duplicated rather than imported since that package doesn't
// export it, with the same zero-pad-stripping caveat its parseVRFName
// documents (a vpc value that legitimately begins with '0' round-trips
// lossily through the padded interface name — an existing, accepted
// limitation this doesn't newly introduce).
var vrfNameRegex = regexp.MustCompile(`^G([A-Za-z0-9]{9})V$`)

func (kernelBackend) ListVRFs() ([]VRFInfo, error) {
	links, err := vrf.ListVRFLinks()
	if err != nil {
		return nil, fmt.Errorf("list VRF interfaces: %w", err)
	}
	infos := make([]VRFInfo, 0, len(links))
	for _, link := range links {
		matches := vrfNameRegex.FindStringSubmatch(link.Name)
		if matches == nil {
			continue // not one of this sidecar's per-VPC VRFs
		}
		vpc := strings.TrimLeft(matches[1], "0")
		if vpc == "" {
			continue // defensive: an all-zero match can't be a real vpc
		}
		infos = append(infos, VRFInfo{VPC: vpc, TableID: link.Table})
	}
	return infos, nil
}

func (kernelBackend) ListRoutes(tableID uint32) ([]RouteInfo, error) {
	var infos []RouteInfo
	// Two passes, not AF_UNSPEC, matching internal/plumbing/vrf.FlushTable's
	// own approach to listing everything in one table across both families.
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: int(tableID)},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			return nil, fmt.Errorf("list routes in table %d: %w", tableID, err)
		}
		for _, route := range routes {
			enc, ok := route.Encap.(*netlink.SEG6Encap)
			if !ok || len(enc.Segments) == 0 || route.Dst == nil {
				continue // not one of this sidecar's seg6 egress routes
			}
			infos = append(infos, RouteInfo{Prefix: route.Dst, SID: enc.Segments[0]})
		}
	}
	return infos, nil
}
