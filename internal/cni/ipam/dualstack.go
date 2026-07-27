// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import "net"

// DualStackAllocator wraps an IPv6 PoolAllocator and an optional IPv4
// IPv4PoolAllocator, allocating from both in a single call. The IPv4
// allocator is optional: when the CNI config does not carry an IPv4 pool,
// DualStackAllocator behaves as IPv6-only.
type DualStackAllocator struct {
	ipv6 *PoolAllocator
	ipv4 *IPv4PoolAllocator
}

// DualStackResult carries the addresses allocated for a single container.
// IPv4Address and IPv4Gateway are nil when the allocator was constructed
// without an IPv4 pool.
type DualStackResult struct {
	IPv6Subnet  *net.IPNet
	IPv6Gateway net.IP
	IPv4Address net.IP
	IPv4Gateway net.IP
}

// NewDualStackAllocator creates a DualStackAllocator. The IPv6 pool is
// always required. If ipv4Pool is empty, the resulting allocator only
// allocates IPv6 addresses (IPv4 fields in DualStackResult are left nil) and
// ipv4LockDir is ignored. ipv4LockDir is passed straight through to
// NewIPv4PoolAllocator (see DefaultIPv4LockDir for the production path).
func NewDualStackAllocator(
	ipv6Pool, ipv6Gateway, ipv4Pool, ipv4Gateway, ipv4LockDir string,
) (*DualStackAllocator, error) {
	ipv6, err := NewPoolAllocator(ipv6Pool, ipv6Gateway, DefaultSubnetLen)
	if err != nil {
		return nil, err
	}

	a := &DualStackAllocator{ipv6: ipv6}

	if ipv4Pool != "" {
		ipv4, err := NewIPv4PoolAllocator(ipv4Pool, ipv4Gateway, ipv4LockDir)
		if err != nil {
			return nil, err
		}
		a.ipv4 = ipv4
	}

	return a, nil
}

// Allocate allocates an IPv6 subnet and, if an IPv4 pool was configured, an
// IPv4 address for the given container ID. Thread-safe (delegates to the
// underlying allocators' own locking).
func (a *DualStackAllocator) Allocate(containerID string) (*DualStackResult, error) {
	ipv6Subnet, err := a.ipv6.Allocate(containerID)
	if err != nil {
		return nil, err
	}

	result := &DualStackResult{
		IPv6Subnet:  ipv6Subnet,
		IPv6Gateway: a.ipv6.Gateway(),
	}

	if a.ipv4 != nil {
		ipv4Addr, err := a.ipv4.Allocate(containerID)
		if err != nil {
			return nil, err
		}
		result.IPv4Address = ipv4Addr
		result.IPv4Gateway = a.ipv4.Gateway()
	}

	return result, nil
}
