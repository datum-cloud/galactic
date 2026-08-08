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

// localIPAMDefaultPool is the IPv6 CIDR pool used when local IPAM is enabled
// but neither static_ip nor ipv6_subnet/ipv4_subnet is set in the ipam
// block. Allocations from it use ipam.DefaultSubnetLen (/96).
const localIPAMDefaultPool = "fd00:10:ff01::/64"

// lockDir is the on-disk allocation-state root both PoolAllocator and
// IPv4PoolAllocator persist to. Overridable in tests so unit tests never
// touch the real production path.
var lockDir = ipam.DefaultLockDir

// allocate allocates addresses for the given container according to conf's
// mode: presence of StaticIP selects the static path; otherwise the pool
// path (either family alone, or both).
func allocate(args *skel.CmdArgs, conf *IPAM) (*IPAMResult, error) {
	if conf.StaticIP != "" {
		return allocateStatic(args, conf)
	}
	return allocatePool(args, conf)
}

// allocateStatic validates and returns the pre-assigned static IPv6 address
// from static_ip. No IPv4 address is ever allocated for static IPAM — it is
// a single fixed address, not a dual-stack pool.
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

// allocatePool allocates a dual-stack, IPv6-only, or IPv4-only pool-based
// endpoint address for the given container, via ipam.DualStackAllocator.
// IPv6Subnet and IPv4Subnet each independently supply a pool CIDR for their
// family; at least one must be set (falling back to localIPAMDefaultPool
// for IPv6 when GALACTIC_IPAM_ENABLE_LOCAL_IPAM is set and both are unset —
// see parseConf, which fills that default in before this ever runs).
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

	var routes []*net.IPNet
	if res.IPv6Subnet != nil {
		routes = append(routes, &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)})
	}
	if res.IPv4Address != nil {
		routes = append(routes, &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)})
	}

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

// deallocate releases whatever allocation containerID holds against conf's
// pools — entirely local: each family's own on-disk marker file is looked
// up directly by containerID (internal/cni/ipam's DeallocateContainer), no
// external state (a CRD read, a Kubernetes client) required. A missing
// allocation for one family (e.g. a v6-only pod, or a partial ADD failure
// that never reached IPv4 allocation) does not prevent cleanup of the
// other — each call is independent and silently no-ops if nothing is
// found.
func deallocate(containerID string, conf *IPAM) {
	if conf.StaticIP != "" {
		// Static allocations don't need deallocation.
		return
	}

	if conf.IPv6Subnet != "" {
		pa, err := ipam.NewPoolAllocator(conf.IPv6Subnet, "", 0, lockDir)
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

// checkAllocation verifies that containerID still holds an allocation
// against every family conf configures — used by CHECK. A static
// allocation has nothing persisted to check (it's validated once, at ADD,
// and never stored), so it always passes. Returns one error per
// missing/unreachable family; nil means every configured family checked
// out.
func checkAllocation(containerID string, conf *IPAM) []error {
	if conf.StaticIP != "" {
		return nil
	}

	var errs []error
	if conf.IPv6Subnet != "" {
		pa, err := ipam.NewPoolAllocator(conf.IPv6Subnet, "", 0, lockDir)
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
