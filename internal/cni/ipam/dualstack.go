// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import "net"

// DualStackAllocator wraps an optional IPv6 and an optional IPv4 pool allocator,
// allocating from whichever are configured in one call. Both are optional: with
// no IPv6 pool it behaves as IPv4-only, and the reverse.
type DualStackAllocator struct {
	ipv6 *PoolAllocator
	ipv4 *IPv4PoolAllocator
}

// DualStackResult carries the addresses allocated for one container. The IPv6
// fields are nil when the allocator was built without an IPv6 pool, and the IPv4
// fields likewise.
type DualStackResult struct {
	IPv6Subnet  *net.IPNet
	IPv6Gateway net.IP
	IPv4Address net.IP
	IPv4Gateway net.IP
}

// NewDualStackAllocator creates a DualStackAllocator. An empty pool for either
// family leaves that family's result fields nil. lockDir passes straight through
// to both underlying allocators: one shared root serves both families, since each
// pool's CIDR namespaces its state into its own subdirectory.
func NewDualStackAllocator(
	ipv6Pool, ipv6Gateway, ipv4Pool, ipv4Gateway, lockDir string,
) (*DualStackAllocator, error) {
	a := &DualStackAllocator{}

	if ipv6Pool != "" {
		ipv6, err := NewPoolAllocator(ipv6Pool, ipv6Gateway, DefaultSubnetLen, lockDir)
		if err != nil {
			return nil, err
		}
		a.ipv6 = ipv6
	}

	if ipv4Pool != "" {
		ipv4, err := NewIPv4PoolAllocator(ipv4Pool, ipv4Gateway, lockDir)
		if err != nil {
			return nil, err
		}
		a.ipv4 = ipv4
	}

	return a, nil
}

// Allocate allocates from whichever pools were configured for the given
// container. Thread-safe, delegating to the underlying allocators' locking.
func (a *DualStackAllocator) Allocate(containerID string) (*DualStackResult, error) {
	result := &DualStackResult{}

	if a.ipv6 != nil {
		ipv6Subnet, err := a.ipv6.Allocate(containerID)
		if err != nil {
			return nil, err
		}
		result.IPv6Subnet = ipv6Subnet
		result.IPv6Gateway = a.ipv6.Gateway()
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
