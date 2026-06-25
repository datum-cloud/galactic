// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ipam provides IPv6 subnet allocation for the Galactic CNI.
// Each allocation returns a subnet (default /80) from a larger CIDR pool.
// Allocations are kept ephemeral in memory; separate CNI plugin processes
// (each invocation is a separate process) rely on the BGPAdvertisement CRD
// annotation to look up the allocated subnet during teardown.
package ipam

import (
	"fmt"
	"net"
	"sync"
)

const (
	// ipv6Bits is the number of bits in an IPv6 address.
	ipv6Bits = 128

	// DefaultSubnetLen is the default prefix length returned per allocation.
	// A /80 gives 2^48 addresses per pod subnet.
	DefaultSubnetLen = 80
)

// PoolAllocator allocates IPv6 subnets from a CIDR pool, tracking
// allocations by subnet CIDR string in memory. All bindings are ephemeral.
type PoolAllocator struct {
	pool        *net.IPNet // the master pool (e.g. fd00:10:ff01::/48)
	subnetLen   int        // prefix length per allocation (e.g. 80)
	gateway     net.IP     // gateway IP address
	poolIP      net.IP     // immutable copy of pool.IP for boundary checks
	allocations sync.Map   // allocated subnet CIDR string -> struct{}{}
	mu          sync.Mutex // serializes Allocate calls
}

// NewPoolAllocator creates a new pool allocator from an IPv6 CIDR pool,
// an optional gateway address, and a subnet prefix length. The pool must be
// an IPv6 prefix with a length of subnetLen or fewer bits. If gateway is
// empty, the first address in the pool (host bits = 1) is used as the
// gateway. If subnetLen is 0, DefaultSubnetLen (80) is used.
func NewPoolAllocator(poolCIDR, gateway string, subnetLen int) (*PoolAllocator, error) {
	_, pool, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse pool CIDR %q: %w", poolCIDR, err)
	}
	if pool.IP.To4() != nil {
		return nil, fmt.Errorf("pool must be IPv6, got IPv4: %s", poolCIDR)
	}

	if subnetLen == 0 {
		subnetLen = DefaultSubnetLen
	}

	mask, _ := pool.Mask.Size()
	if mask > subnetLen {
		return nil, fmt.Errorf("pool prefix length %d is longer than subnet length %d", mask, subnetLen)
	}

	pa := &PoolAllocator{
		pool:        pool,
		subnetLen:   subnetLen,
		poolIP:      make(net.IP, ipv6Bits/8),
		allocations: sync.Map{},
	}
	copy(pa.poolIP, pool.IP)

	if gateway != "" {
		gwIP := net.ParseIP(gateway)
		if gwIP == nil {
			return nil, fmt.Errorf("invalid gateway IP: %s", gateway)
		}
		if !pool.Contains(gwIP) {
			return nil, fmt.Errorf("gateway %s is not in pool %s", gateway, poolCIDR)
		}
		pa.gateway = gwIP.To16()
	} else {
		// Default gateway: first usable address (host bits = 1)
		gw := make(net.IP, ipv6Bits/8)
		copy(gw, pool.IP)
		gw[ipv6Bits/8-1] = 1
		pa.gateway = gw
	}

	return pa, nil
}

// Allocate assigns the next available IPv6 subnet from the pool for the
// given container ID. Returns the allocated subnet CIDR or an error if the
// pool is exhausted. Thread-safe.
func (a *PoolAllocator) Allocate(containerID string) (*net.IPNet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Collect currently allocated subnets for fast lookup.
	used := make(map[string]struct{})
	a.allocations.Range(func(key, value any) bool {
		used[key.(string)] = struct{}{}
		return true
	})

	// Iterate subnet boundaries within the pool.
	subnetStart := make(net.IP, ipv6Bits/8)
	copy(subnetStart, a.poolIP)

	for ; a.pool.Contains(subnetStart); subnetStart = incSubnet(subnetStart, a.subnetLen) {
		// Build the subnet CIDR for this boundary.
		subnet := &net.IPNet{
			IP:   make(net.IP, ipv6Bits/8),
			Mask: net.CIDRMask(a.subnetLen, ipv6Bits),
		}
		copy(subnet.IP, subnetStart)
		subnetStr := subnet.String()

		// Skip already allocated.
		if _, ok := used[subnetStr]; ok {
			continue
		}

		// Allocate.
		a.allocations.Store(subnetStr, struct{}{})
		return subnet, nil
	}

	return nil, fmt.Errorf("pool %s exhausted (subnet /%d)", a.pool.String(), a.subnetLen)
}

// Deallocate removes the allocation for the given subnet CIDR string.
// Silently ignores unknown subnets.
func (a *PoolAllocator) Deallocate(subnetCIDR string) {
	a.allocations.Delete(subnetCIDR)
}

// IsAllocated reports whether the given subnet CIDR string is actively allocated.
func (a *PoolAllocator) IsAllocated(subnetCIDR string) bool {
	_, ok := a.allocations.Load(subnetCIDR)
	return ok
}

// Gateway returns the gateway IP for the pool.
func (a *PoolAllocator) Gateway() net.IP {
	return a.gateway
}

// StaticAllocator validates and returns a static IPv6 address.
type StaticAllocator struct{}

// NewStaticAllocator creates a new static allocator.
func NewStaticAllocator() *StaticAllocator {
	return &StaticAllocator{}
}

// Allocate validates the given IPv6 address and returns it.
// The address must be a well-formed IPv6 address.
func (a *StaticAllocator) Allocate(containerID, addr string) (net.IP, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv6 address: %s", addr)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("static allocator requires IPv6, got IPv4: %s", addr)
	}
	return ip.To16(), nil
}

// incSubnet increments an IP by one subnet step and returns it in place.
// The step size is 2^(128-subnetLen), advancing to the next subnet boundary.
func incSubnet(ip net.IP, subnetLen int) net.IP {
	// Zero out host bits (bytes after the network boundary).
	boundary := subnetLen / 8
	for i := boundary; i < len(ip); i++ {
		ip[i] = 0
	}
	// Increment the first host byte (just past the network prefix).
	for i := boundary; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	return ip
}
