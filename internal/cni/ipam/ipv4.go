// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"fmt"
	"net"
	"sync"
)

const (
	// ipv4Bits is the number of bits in an IPv4 address.
	ipv4Bits = 32
)

// IPv4PoolAllocator allocates individual IPv4 /32 addresses from a CIDR pool,
// tracking allocations by address string in memory. All bindings are
// ephemeral. Four addresses in the pool are reserved and never handed out:
// the network address (first address), the gateway address (network address
// + 1, or an explicit gateway), the second-to-last address (platform
// reserved), and the last address (broadcast-equivalent).
type IPv4PoolAllocator struct {
	pool        *net.IPNet // the master pool (e.g. a /20 site subnet)
	gateway     net.IP     // gateway IP address
	allocations sync.Map   // allocated address string -> struct{}{}
	mu          sync.Mutex // serializes Allocate calls
}

// NewIPv4PoolAllocator creates a new IPv4 pool allocator from a CIDR pool and
// an optional gateway address. The pool must be an IPv4 prefix. If gateway is
// empty, the network address plus 1 is used as the gateway.
func NewIPv4PoolAllocator(poolCIDR, gateway string) (*IPv4PoolAllocator, error) {
	_, pool, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse pool CIDR %q: %w", poolCIDR, err)
	}
	pool4 := pool.IP.To4()
	if pool4 == nil {
		return nil, fmt.Errorf("pool must be IPv4, got IPv6: %s", poolCIDR)
	}
	pool.IP = pool4

	a := &IPv4PoolAllocator{
		pool:        pool,
		allocations: sync.Map{},
	}

	if gateway != "" {
		gwIP := net.ParseIP(gateway)
		if gwIP == nil {
			return nil, fmt.Errorf("invalid gateway IP: %s", gateway)
		}
		gwIP4 := gwIP.To4()
		if gwIP4 == nil {
			return nil, fmt.Errorf("gateway must be IPv4, got IPv6: %s", gateway)
		}
		if !pool.Contains(gwIP4) {
			return nil, fmt.Errorf("gateway %s is not in pool %s", gateway, poolCIDR)
		}
		a.gateway = gwIP4
	} else {
		a.gateway = offsetIP4(pool4, 1)
	}

	return a, nil
}

// Allocate assigns the next available IPv4 /32 address from the pool for the
// given container ID, skipping reserved addresses (the network address, the
// gateway, the second-to-last address, and the last address of the pool).
// Returns an error if the pool is exhausted. Thread-safe.
func (a *IPv4PoolAllocator) Allocate(_ string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	used := make(map[string]struct{})
	a.allocations.Range(func(key, _ any) bool {
		used[key.(string)] = struct{}{}
		return true
	})

	reserved := a.reservedAddresses()

	ones, bits := a.pool.Mask.Size()
	total := uint64(1) << uint(bits-ones)

	for i := range total {
		addr := offsetIP4(a.pool.IP, i)
		addrStr := addr.String()

		if _, ok := reserved[addrStr]; ok {
			continue
		}
		if _, ok := used[addrStr]; ok {
			continue
		}

		a.allocations.Store(addrStr, struct{}{})
		return addr, nil
	}

	return nil, fmt.Errorf("pool %s exhausted", a.pool.String())
}

// Deallocate removes the allocation for the given address string. Silently
// ignores unknown addresses.
func (a *IPv4PoolAllocator) Deallocate(addr string) {
	a.allocations.Delete(addr)
}

// IsAllocated reports whether the given address string is actively allocated.
func (a *IPv4PoolAllocator) IsAllocated(addr string) bool {
	_, ok := a.allocations.Load(addr)
	return ok
}

// Gateway returns the gateway IP for the pool.
func (a *IPv4PoolAllocator) Gateway() net.IP {
	return a.gateway
}

// reservedAddresses returns the set of addresses in the pool that are never
// handed out by Allocate: the network address, the gateway address, the
// second-to-last address, and the last address.
func (a *IPv4PoolAllocator) reservedAddresses() map[string]struct{} {
	ones, bits := a.pool.Mask.Size()
	total := uint64(1) << uint(bits-ones)

	reserved := map[string]struct{}{
		a.pool.IP.String():                     {},
		a.gateway.String():                     {},
		offsetIP4(a.pool.IP, total-2).String(): {},
		offsetIP4(a.pool.IP, total-1).String(): {},
	}
	return reserved
}

// offsetIP4 returns the IPv4 address at base + offset, wrapping within the
// 32-bit address space.
func offsetIP4(base net.IP, offset uint64) net.IP {
	baseVal := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	val := baseVal + uint32(offset)

	ip := make(net.IP, ipv4Bits/8)
	ip[0] = byte(val >> 24)
	ip[1] = byte(val >> 16)
	ip[2] = byte(val >> 8)
	ip[3] = byte(val)
	return ip
}
