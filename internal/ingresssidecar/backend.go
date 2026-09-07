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

// Backend is the kernel-facing interface Store converges VRF and SRv6 egress
// route state against. kernelBackend wires it to the same primitives the CNI
// pod-attachment path uses; tests use a fake.
type Backend interface {
	// EnsureVRF creates (idempotently) the per-VPC Linux VRF device and
	// returns its kernel routing table ID.
	EnsureVRF(vpc string) (tableID uint32, err error)
	// RemoveVRF tears down the per-VPC VRF device. Callers must only call it
	// once no route for this VPC remains live or in its grace period, since
	// deleting out from under a live sibling breaks it.
	RemoveVRF(vpc string) error
	// EnsureRoute idempotently installs the encapsulating route for prefix,
	// toward sid, in tableID.
	EnsureRoute(prefix *net.IPNet, sid net.IP, tableID uint32) error
	// RemoveRoute removes the route EnsureRoute installed.
	RemoveRoute(prefix *net.IPNet, tableID uint32) error
	// ListVRFs returns every per-VPC VRF device present on the host, resolved
	// back to its owning VPC, for the startup inventory.
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

// NewKernelBackend returns the production Backend, wired to real kernel state.
// Requires CAP_NET_ADMIN.
func NewKernelBackend() Backend { return kernelBackend{} }

func (kernelBackend) EnsureVRF(vpc string) (uint32, error) {
	if err := vrf.Add(vpc); err != nil {
		return 0, fmt.Errorf("create VRF for vpc %s: %w", vpc, err)
	}
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		return 0, fmt.Errorf("resolve VRF table ID for vpc %s: %w", vpc, err)
	}
	// Without this, the egress route entries below have nothing attached in
	// this pod's namespace to read them. vpc is threaded through, not just
	// tableID, so this can also derive and assign the VPC's return-path gateway
	// address when one is configured.
	if err := ensureEgressDatapath(vpc, tableID); err != nil {
		return 0, fmt.Errorf("attach eBPF egress datapath for vpc %s: %w", vpc, err)
	}
	return tableID, nil
}

func (kernelBackend) RemoveVRF(vpc string) error {
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		return nil // VRF already gone — idempotent, matching vrf.Delete's own stance
	}
	// Torn down before the interface is removed below, while its ifindex can
	// still be resolved.
	if err := removeEgressDatapath(tableID); err != nil {
		return fmt.Errorf("detach eBPF egress datapath for vpc %s: %w", vpc, err)
	}
	if err := vrf.Delete(vpc); err != nil {
		return fmt.Errorf("delete VRF for vpc %s: %w", vpc, err)
	}
	return nil
}

func (kernelBackend) EnsureRoute(prefix *net.IPNet, sid net.IP, tableID uint32) error {
	if err := srv6.RouteEgressAdd(prefix, sid, tableID); err != nil {
		return fmt.Errorf("install seg6 route for %s: %w", prefix, err)
	}
	// Without this, nothing routes this pod's outbound traffic for prefix into
	// the VRF interface the entry above was just registered against.
	if err := ensureRedirectRoute(prefix, tableID); err != nil {
		return fmt.Errorf("install main-table redirect route for %s: %w", prefix, err)
	}
	return nil
}

func (kernelBackend) RemoveRoute(prefix *net.IPNet, tableID uint32) error {
	if err := removeRedirectRoute(prefix); err != nil {
		return fmt.Errorf("remove main-table redirect route for %s: %w", prefix, err)
	}
	if err := srv6.RouteEgressDel(prefix, tableID); err != nil {
		return fmt.Errorf("remove seg6 route for %s: %w", prefix, err)
	}
	return nil
}

// vrfNameRegex matches the interface name generated for a VPC: a leading
// letter, nine zero-padded base62 characters, and a trailing letter.
//
// Duplicated from the garbage collector rather than imported, that package not
// exporting it, and carrying the same caveat: a VPC value legitimately
// beginning with "0" round-trips lossily through the padded name.
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
