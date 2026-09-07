// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/containernetworking/cni/pkg/skel"

	"go.datum.net/galactic/internal/cni/ipam"
)

// localIPAMDefaultPool is the IPv6 pool used when local IPAM is enabled but the
// ipam block names no static address and no subnet.
const localIPAMDefaultPool = "fd00:10:ff01::/64"

// lockDir is the on-disk allocation-state root both allocators persist to.
// Overridable so tests never touch the production path.
var lockDir = ipam.DefaultLockDir

// allocate assigns addresses for a container according to conf's mode: an
// addresses list selects the pre-decided path, a static address the legacy
// path, and otherwise the pool path, for either family alone or both.
func allocate(args *skel.CmdArgs, conf *IPAM) (*IPAMResult, error) {
	switch {
	case len(conf.Addresses) > 0:
		return allocateAddresses(args, conf)
	case conf.StaticIP != "":
		return allocateStatic(args, conf)
	default:
		return allocatePool(args, conf)
	}
}

// allocateAddresses assigns the addresses the config already carries, exactly
// as given, prefix lengths included and gateways honored. Nothing is allocated
// and nothing is persisted: the addresses belong to whoever decided them.
func allocateAddresses(args *skel.CmdArgs, conf *IPAM) (*IPAMResult, error) {
	parsed, err := parseAddresses(conf.Addresses)
	if err != nil {
		return nil, err
	}

	slog.Debug("IPAM: assigned pre-decided addresses", "containerID", args.ContainerID,
		"ipv6Subnet", parsed.ipv6, "ipv6Gateway", parsed.ipv6Gateway,
		"ipv4Address", parsed.ipv4, "ipv4Gateway", parsed.ipv4Gateway)

	return &IPAMResult{
		IPv6Subnet:  parsed.ipv6,
		IPv6Gateway: parsed.ipv6Gateway,
		IPv4Address: parsed.ipv4,
		IPv4Gateway: parsed.ipv4Gateway,
		Routes:      defaultRoutes(parsed.ipv6 != nil, parsed.ipv4 != nil),
	}, nil
}

// defaultRoutes returns the per-family default route each configured family
// gets, the same set the pool path publishes.
func defaultRoutes(ipv6, ipv4 bool) []*net.IPNet {
	var routes []*net.IPNet
	if ipv6 {
		routes = append(routes, &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)})
	}
	if ipv4 {
		routes = append(routes, &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)})
	}
	return routes
}

// allocateStatic validates and returns the pre-assigned static IPv6 address. No
// IPv4 address is ever allocated on this path, it being a single fixed address
// rather than a pool.
func allocateStatic(args *skel.CmdArgs, conf *IPAM) (*IPAMResult, error) {
	alloc := ipam.NewStaticAllocator()
	allocIP, err := alloc.Allocate(args.ContainerID, conf.StaticIP)
	if err != nil {
		return nil, fmt.Errorf("allocate static IP: %w", err)
	}
	subnet := &net.IPNet{
		IP:   allocIP,
		Mask: net.CIDRMask(64, 128),
	}
	slog.Debug("IPAM: allocated static", "containerID", args.ContainerID, "subnet", subnet)
	return &IPAMResult{IPv6Subnet: subnet}, nil
}

// allocatePool allocates a dual-stack, IPv6-only, or IPv4-only endpoint address
// for a container. Each family's subnet independently supplies a pool, and at
// least one must be set; config parsing fills in the default IPv6 pool before
// this runs when local IPAM is enabled and neither is.
func allocatePool(args *skel.CmdArgs, conf *IPAM) (*IPAMResult, error) {
	if conf.IPv6Subnet == "" && conf.IPv4Subnet == "" {
		return nil, errors.New("ipam.ipv6_subnet or ipam.ipv4_subnet is required (or enable GALACTIC_IPAM_ENABLE_LOCAL_IPAM)")
	}

	alloc, err := ipam.NewDualStackAllocator(conf.IPv6Subnet, "", conf.IPv4Subnet, "", lockDir)
	if err != nil {
		return nil, fmt.Errorf("create dual-stack allocator: %w", err)
	}

	res, err := alloc.Allocate(args.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("allocate dual-stack addresses: %w", err)
	}

	routes := defaultRoutes(res.IPv6Subnet != nil, res.IPv4Address != nil)

	slog.Debug("IPAM: allocated", "containerID", args.ContainerID,
		"ipv6Subnet", res.IPv6Subnet, "ipv6Gateway", res.IPv6Gateway,
		"ipv4Address", res.IPv4Address, "ipv4Gateway", res.IPv4Gateway)

	return &IPAMResult{
		IPv6Subnet:  res.IPv6Subnet,
		IPv6Gateway: res.IPv6Gateway,
		IPv4Address: res.IPv4Address,
		IPv4Gateway: res.IPv4Gateway,
		Routes:      routes,
	}, nil
}

// effectiveIPv6Subnet returns the configured IPv6 subnet when either family's
// subnet was explicitly set, and otherwise the default pool directly.
//
// Returning it directly, rather than re-deriving it from the local-IPAM
// environment flag, is what keeps deallocation and checking independent of that
// flag still agreeing at DEL or CHECK time with what it resolved to at ADD. A
// flag that flipped in between would leave an empty subnet here, silently
// skipping cleanup and leaking the allocation.
func effectiveIPv6Subnet(conf *IPAM) string {
	if conf.IPv6Subnet != "" || conf.IPv4Subnet != "" {
		return conf.IPv6Subnet
	}
	return localIPAMDefaultPool
}

// deallocate releases whatever allocation containerID holds against conf's
// pools. It is entirely local: each family's marker file is looked up by
// container ID, needing no CRD read or API client.
//
// A missing allocation for one family, from an IPv6-only pod or a partial ADD
// failure, does not prevent cleanup of the other: each call is independent and
// silently does nothing when it finds none.
func deallocate(containerID string, conf *IPAM) {
	if len(conf.Addresses) > 0 {
		// Externally decided addresses were never allocated here, so there is nothing to release.
		return
	}

	if conf.StaticIP != "" {
		// Static allocations don't need deallocation.
		return
	}

	if ipv6Subnet := effectiveIPv6Subnet(conf); ipv6Subnet != "" {
		pa, err := ipam.NewPoolAllocator(ipv6Subnet, "", 0, lockDir)
		if err != nil {
			slog.Warn("IPAM: failed to build IPv6 pool allocator for deallocation, skipping", "err", err,
				"containerID", containerID)
		} else if subnet, ok := pa.DeallocateContainer(containerID); ok {
			slog.Debug("IPAM: deallocated IPv6", "containerID", containerID, "subnet", subnet)
		}
	}

	if conf.IPv4Subnet != "" {
		pa, err := ipam.NewIPv4PoolAllocator(conf.IPv4Subnet, "", lockDir)
		if err != nil {
			slog.Warn("IPAM: failed to build IPv4 pool allocator for deallocation, skipping", "err", err,
				"containerID", containerID)
		} else if addr, ok := pa.DeallocateContainer(containerID); ok {
			slog.Debug("IPAM: deallocated IPv4", "containerID", containerID, "address", addr)
		}
	}
}

// checkAllocation verifies containerID still holds an allocation against every
// family conf configures, returning one error per missing family and nil when
// all check out. An externally decided address has nothing persisted to check,
// being validated once at ADD and never stored, so it always passes.
func checkAllocation(containerID string, conf *IPAM) []error {
	if len(conf.Addresses) > 0 || conf.StaticIP != "" {
		return nil
	}

	var errs []error
	if ipv6Subnet := effectiveIPv6Subnet(conf); ipv6Subnet != "" {
		pa, err := ipam.NewPoolAllocator(ipv6Subnet, "", 0, lockDir)
		if err != nil {
			errs = append(errs, fmt.Errorf("open IPv6 pool: %w", err))
		} else if _, ok := pa.LookupContainer(containerID); !ok {
			errs = append(errs, errors.New("no IPv6 allocation found for container"))
		}
	}
	if conf.IPv4Subnet != "" {
		pa, err := ipam.NewIPv4PoolAllocator(conf.IPv4Subnet, "", lockDir)
		if err != nil {
			errs = append(errs, fmt.Errorf("open IPv4 pool: %w", err))
		} else if _, ok := pa.LookupContainer(containerID); !ok {
			errs = append(errs, errors.New("no IPv4 allocation found for container"))
		}
	}
	return errs
}
