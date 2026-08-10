// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// ipv4Bits is the number of bits in an IPv4 address.
	ipv4Bits = 32

	// ipv4LockFileName is the flock target within each pool's state
	// directory; every other entry in that directory is an allocation
	// marker file named after the address it reserves.
	ipv4LockFileName = "lock"
)

// IPv4PoolAllocator allocates individual IPv4 /32 addresses from a CIDR pool.
// Unlike PoolAllocator's ephemeral in-memory tracking, IPv4PoolAllocator
// persists each allocation as a marker file under a lock directory, keyed by
// the pool CIDR, and guards reads/writes of that state with a cross-process
// flock. This is required because PR #740's IPv4 pool is a site-wide /20
// shared by every VPC at that site: each CNI invocation is a separate OS
// process, so two pods in different VPCs concurrently ADDing on the same
// node construct independent allocator instances against the identical pool
// — an in-memory-only "used" set (as PoolAllocator uses for IPv6, where each
// VPCAttachment's pool is exclusively its own) would let both instances
// allocate the same address. Four addresses in the pool are reserved and
// never handed out: the network address (first address), the gateway
// address (network address + 1, or an explicit gateway), the second-to-last
// address (platform reserved), and the last address (broadcast-equivalent).
type IPv4PoolAllocator struct {
	pool     *net.IPNet // the master pool (e.g. a /20 site subnet)
	gateway  net.IP     // gateway IP address
	mu       sync.Mutex // serializes Allocate/Deallocate within this process
	stateDir string     // directory holding the lock file and one allocation marker file per allocated address
	state    lockedState
}

// NewIPv4PoolAllocator creates a new IPv4 pool allocator from a CIDR pool and
// an optional gateway address. The pool must be an IPv4 prefix. If gateway is
// empty, the network address plus 1 is used as the gateway. lockDir is the
// parent directory for this pool's on-disk lock and allocation state (see
// DefaultLockDir for the production path); it must not be empty, and a
// pool-scoped subdirectory under it is created if it doesn't already exist.
func NewIPv4PoolAllocator(poolCIDR, gateway, lockDir string) (*IPv4PoolAllocator, error) {
	_, pool, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse pool CIDR %q: %w", poolCIDR, err)
	}
	pool4 := pool.IP.To4()
	if pool4 == nil {
		return nil, fmt.Errorf("pool must be IPv4, got IPv6: %s", poolCIDR)
	}
	pool.IP = pool4

	if lockDir == "" {
		return nil, errors.New("lockDir must not be empty")
	}

	a := &IPv4PoolAllocator{
		pool: pool,
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

	stateDir := filepath.Join(lockDir, sanitizePoolDirName(pool.String()))
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create pool state dir %q: %w", stateDir, err)
	}
	a.stateDir = stateDir
	a.state = lockedState{stateDir: stateDir, lockFileName: ipv4LockFileName}

	return a, nil
}

// Allocate assigns the next available IPv4 /32 address from the pool for the
// given container ID, skipping reserved addresses (the network address, the
// gateway, the second-to-last address, and the last address of the pool). If
// containerID already holds an allocation in this pool, that same address is
// returned rather than a fresh one being handed out — see
// PoolAllocator.Allocate's doc comment (IPv6) for why this idempotency check
// matters for CNI ADD retries. Returns an error if the pool is exhausted.
// The read-modify-write against the on-disk allocation state is serialized
// both within this process (via mu) and across processes sharing the same
// pool (via a flock on the pool's lock file), so concurrent ADDs from
// different VPCs on the same node never return the same address.
func (a *IPv4PoolAllocator) Allocate(containerID string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var result net.IP
	err := a.state.withLock(func() error {
		if addrStr, ok := a.state.findContainerMarkerLocked(containerID); ok {
			result = net.ParseIP(addrStr).To4()
			return nil
		}

		used, err := a.usedAddresses()
		if err != nil {
			return err
		}

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

			markerPath := filepath.Join(a.stateDir, addrStr)
			if err := os.WriteFile(markerPath, []byte(containerID), 0o600); err != nil {
				return fmt.Errorf("write allocation marker %q: %w", markerPath, err)
			}
			result = addr
			return nil
		}

		return fmt.Errorf("pool %s exhausted", a.pool.String())
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Deallocate removes the allocation for the given address string. Silently
// ignores unknown addresses. Serialized the same way as Allocate.
func (a *IPv4PoolAllocator) Deallocate(addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	_ = a.state.withLock(func() error {
		return os.Remove(filepath.Join(a.stateDir, addr))
	})
}

// LookupContainer reports the address, if any, allocated to containerID,
// without removing it — used by CHECK to confirm an allocation is still in
// place. Returns ("", false) if none is found.
func (a *IPv4PoolAllocator) LookupContainer(containerID string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var addr string
	var ok bool
	_ = a.state.withLock(func() error {
		addr, ok = a.state.findContainerMarkerLocked(containerID)
		return nil
	})
	return addr, ok
}

// DeallocateContainer removes the allocation, if any, held by containerID,
// without the caller needing to already know the allocated address —
// mirrors PoolAllocator.DeallocateContainer (IPv6); see its doc comment for
// why the scan and the removal must happen under a single flock acquisition.
// Returns the deallocated address and true if one was found; ("", false)
// otherwise.
func (a *IPv4PoolAllocator) DeallocateContainer(containerID string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var addr string
	var ok bool
	_ = a.state.withLock(func() error {
		found, wasFound := a.state.findContainerMarkerLocked(containerID)
		if !wasFound {
			return nil
		}
		addr = found
		ok = true
		return os.Remove(filepath.Join(a.stateDir, found))
	})
	if !ok {
		return "", false
	}
	return addr, true
}

// IsAllocated reports whether the given address string is actively
// allocated, by checking for its on-disk marker file.
func (a *IPv4PoolAllocator) IsAllocated(addr string) bool {
	_, err := os.Stat(filepath.Join(a.stateDir, addr))
	return err == nil
}

// usedAddresses reads the pool's state directory and returns the set of
// addresses currently marked allocated by any process sharing this pool.
// Callers must hold both mu and the pool's flock.
func (a *IPv4PoolAllocator) usedAddresses() (map[string]struct{}, error) {
	entries, err := a.state.entries()
	if err != nil {
		return nil, err
	}

	used := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		used[e.Name()] = struct{}{}
	}
	return used, nil
}

// sanitizePoolDirName converts a pool CIDR string into a name safe to use as
// a single path component (CIDRs contain a '/', which isn't).
func sanitizePoolDirName(poolCIDR string) string {
	return strings.ReplaceAll(poolCIDR, "/", "-")
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
