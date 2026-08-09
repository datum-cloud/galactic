// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ipam provides IPv6 subnet allocation for the Galactic CNI. Each
// allocation returns a subnet (default /96) from a larger CIDR pool (e.g. a
// /64 region subnet).
//
// Allocations persist as an on-disk marker file per allocated subnet, keyed
// by the pool CIDR (mirroring IPv4PoolAllocator's own scheme) — required
// because each CNI ADD/DEL is a separate OS process: an in-memory-only
// record (as this package used before) is discarded the moment the ADD
// process that created it exits, leaving DEL with nothing to look up.
package ipam

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	// ipv6Bits is the number of bits in an IPv6 address.
	ipv6Bits = 128

	// DefaultSubnetLen is the default prefix length returned per allocation.
	// A /96 gives 2^32 addresses per pod subnet.
	DefaultSubnetLen = 96

	// poolLockFileName is the flock target within each pool's state
	// directory; every other entry in that directory is an allocation
	// marker file named after the subnet it reserves.
	poolLockFileName = "lock"
)

// DefaultLockDir is the well-known parent directory for the node-local
// on-disk lock and allocation state both PoolAllocator (IPv6) and
// IPv4PoolAllocator use to stay correct across separate CNI plugin
// invocations. Both families share one root — each pool's own CIDR
// namespaces its state into a distinct subdirectory (sanitizePoolDirName),
// so an IPv6 pool and an IPv4 pool never collide here.
const DefaultLockDir = "/var/lib/cni/galactic-ipam"

// PoolAllocator allocates IPv6 subnets from a CIDR pool, persisting each
// allocation as a marker file under a lock directory, guarded by a
// cross-process flock — see IPv4PoolAllocator's own doc comment for why
// this is required rather than optional.
type PoolAllocator struct {
	pool      *net.IPNet // the master pool (e.g. a /64 region subnet)
	subnetLen int        // prefix length per allocation (e.g. 96)
	gateway   net.IP     // gateway IP address
	poolIP    net.IP     // immutable copy of pool.IP for boundary checks
	reserved  string     // subnet CIDR string containing the gateway; never allocated
	mu        sync.Mutex // serializes Allocate/Deallocate within this process
	stateDir  string     // directory holding the lock file and one allocation marker file per allocated subnet
	state     lockedState
}

// NewPoolAllocator creates a new pool allocator from an IPv6 CIDR pool, an
// optional gateway address, a subnet prefix length, and a parent directory
// for this pool's on-disk lock and allocation state (see DefaultLockDir for
// the production path; lockDir must not be empty). The pool must be an
// IPv6 prefix with a length of subnetLen or fewer bits (e.g. a /64 region
// subnet when subnetLen is the default /96, though any pool length <=
// subnetLen is accepted). If gateway is empty, the first address in the pool
// (host bits = 1) is used as the gateway. If subnetLen is 0, DefaultSubnetLen
// (96) is used. The subnet containing the gateway is reserved and never
// handed out by Allocate — otherwise the endpoint owning that subnet could
// self-assign the gateway's own address to one of its secondary/pod
// addresses, colliding with the address every other endpoint in the pool
// routes its default route through.
func NewPoolAllocator(poolCIDR, gateway string, subnetLen int, lockDir string) (*PoolAllocator, error) {
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

	if lockDir == "" {
		return nil, errors.New("lockDir must not be empty")
	}

	pa := &PoolAllocator{
		pool:      pool,
		subnetLen: subnetLen,
		poolIP:    make(net.IP, ipv6Bits/8),
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

	reservedSubnet := &net.IPNet{
		IP:   pa.gateway.Mask(net.CIDRMask(subnetLen, ipv6Bits)),
		Mask: net.CIDRMask(subnetLen, ipv6Bits),
	}
	pa.reserved = reservedSubnet.String()

	stateDir := filepath.Join(lockDir, sanitizePoolDirName(pool.String()))
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create pool state dir %q: %w", stateDir, err)
	}
	pa.stateDir = stateDir
	pa.state = lockedState{stateDir: stateDir, lockFileName: poolLockFileName}

	return pa, nil
}

// Allocate assigns the next available IPv6 subnet from the pool for the
// given container ID, skipping the subnet that contains the pool's gateway
// address and any subnet another allocation already holds (per the on-disk
// marker files, so this is correct across separate CNI plugin invocations
// on the same pool). If containerID already holds an allocation in this
// pool, that same subnet is returned rather than a fresh one being handed
// out — the CNI spec permits a runtime to retry ADD for the same container
// after a transient failure, and without this check each retry would leak
// the marker file from the previous attempt (findContainerMarker only ever
// returns the first match, so only one of the leaked markers would ever be
// recoverable via DEL). Returns the allocated subnet CIDR or an error if the
// pool is exhausted. Thread-safe.
func (a *PoolAllocator) Allocate(containerID string) (*net.IPNet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var result *net.IPNet
	err := a.state.withLock(func() error {
		if name, ok := a.state.findContainerMarkerLocked(containerID); ok {
			existing, err := parseAllocatedSubnet(desanitizeMarkerName(name))
			if err != nil {
				return fmt.Errorf("parse existing allocation marker %q: %w", name, err)
			}
			result = existing
			return nil
		}

		used, err := a.usedSubnets()
		if err != nil {
			return err
		}

		// Iterate subnet boundaries within the pool.
		subnetStart := make(net.IP, ipv6Bits/8)
		copy(subnetStart, a.poolIP)

		for ; a.pool.Contains(subnetStart); subnetStart = incSubnet(subnetStart, a.subnetLen) {
			subnet := &net.IPNet{
				IP:   make(net.IP, ipv6Bits/8),
				Mask: net.CIDRMask(a.subnetLen, ipv6Bits),
			}
			copy(subnet.IP, subnetStart)
			subnetStr := subnet.String()

			if subnetStr == a.reserved {
				continue
			}
			if _, ok := used[subnetStr]; ok {
				continue
			}

			markerPath := filepath.Join(a.stateDir, sanitizePoolDirName(subnetStr))
			if err := os.WriteFile(markerPath, []byte(containerID), 0o600); err != nil {
				return fmt.Errorf("write allocation marker %q: %w", markerPath, err)
			}
			result = subnet
			return nil
		}

		return fmt.Errorf("pool %s exhausted (subnet /%d)", a.pool.String(), a.subnetLen)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// usedSubnets reads the pool's state directory and returns the set of
// subnet CIDR strings currently marked allocated. Callers must hold both mu
// and the pool's flock.
func (a *PoolAllocator) usedSubnets() (map[string]struct{}, error) {
	entries, err := a.state.entries()
	if err != nil {
		return nil, err
	}
	used := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		used[desanitizeMarkerName(e.Name())] = struct{}{}
	}
	return used, nil
}

// Deallocate removes the allocation for the given subnet CIDR string.
// Silently ignores unknown subnets. Serialized the same way as Allocate.
// Callers that only know the containerID (not the allocated value) should
// use DeallocateContainer instead.
func (a *PoolAllocator) Deallocate(subnetCIDR string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	_ = a.state.withLock(func() error {
		return os.Remove(filepath.Join(a.stateDir, sanitizePoolDirName(subnetCIDR)))
	})
}

// LookupContainer reports the subnet CIDR, if any, allocated to
// containerID, without removing it — used by CHECK to confirm an
// allocation is still in place. Returns ("", false) if none is found.
func (a *PoolAllocator) LookupContainer(containerID string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var name string
	var ok bool
	_ = a.state.withLock(func() error {
		name, ok = a.state.findContainerMarkerLocked(containerID)
		return nil
	})
	if !ok {
		return "", false
	}
	return desanitizeMarkerName(name), true
}

// DeallocateContainer removes the allocation, if any, held by containerID,
// without the caller needing to already know the allocated subnet — the
// on-disk marker file records which containerID holds each subnet, so this
// is a direct scan of this pool's own state, no external lookup (e.g. a
// CRD read) required. The scan and the removal happen under a single flock
// acquisition (via lockedState.withLock) so a concurrent process sharing
// this pool can never interleave between them. Returns the deallocated
// subnet CIDR and true if one was found; ("", false) otherwise.
func (a *PoolAllocator) DeallocateContainer(containerID string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var subnet string
	var ok bool
	_ = a.state.withLock(func() error {
		name, found := a.state.findContainerMarkerLocked(containerID)
		if !found {
			return nil
		}
		subnet = desanitizeMarkerName(name)
		ok = true
		return os.Remove(filepath.Join(a.stateDir, name))
	})
	if !ok {
		return "", false
	}
	return subnet, true
}

// IsAllocated reports whether the given subnet CIDR string is actively
// allocated, by checking for its on-disk marker file.
func (a *PoolAllocator) IsAllocated(subnetCIDR string) bool {
	_, err := os.Stat(filepath.Join(a.stateDir, sanitizePoolDirName(subnetCIDR)))
	return err == nil
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
func (a *StaticAllocator) Allocate(_ string, addr string) (net.IP, error) {
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
//
// Only bytes strictly after the network boundary are zeroed on each call; the
// boundary byte itself is left untouched so it can keep counting up across
// repeated calls on the same IP (as Allocate does when walking pool
// boundaries). Zeroing the boundary byte on every call — as an earlier
// version of this function did — reset the counter back to its just-computed
// value each time, so a chained sequence of calls never advanced past the
// second subnet in the pool.
func incSubnet(ip net.IP, subnetLen int) net.IP {
	// Zero out host bits strictly after the network boundary byte.
	boundary := subnetLen / 8
	for i := boundary + 1; i < len(ip); i++ {
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

// desanitizeMarkerName reverses sanitizePoolDirName's "/" -> "-" replacement
// for a subnet CIDR marker filename. A CIDR string carries exactly one "/",
// so replacing the first "-" back is unambiguous (subnet strings otherwise
// contain only hex digits and ":").
func desanitizeMarkerName(name string) string {
	before, after, found := strings.Cut(name, "-")
	if !found {
		return name
	}
	return before + "/" + after
}

// parseAllocatedSubnet parses a subnet CIDR string previously produced by
// Allocate (via (*net.IPNet).String()) back into a *net.IPNet, preserving
// its IP exactly as allocated. net.ParseCIDR is deliberately not used here:
// it returns the *masked* network address, which would zero out incSubnet's
// per-subnet counter byte — the byte incSubnet advances sits inside what a
// strict /subnetLen mask treats as host bits (see incSubnet's own doc
// comment), so re-masking a stored subnet string would silently collapse
// every allocated subnet in the pool back down to the same reserved-subnet
// address.
func parseAllocatedSubnet(cidr string) (*net.IPNet, error) {
	ipStr, prefixStr, found := strings.Cut(cidr, "/")
	if !found {
		return nil, fmt.Errorf("missing '/' in subnet CIDR %q", cidr)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP in subnet CIDR %q", cidr)
	}
	prefixLen, err := strconv.Atoi(prefixStr)
	if err != nil {
		return nil, fmt.Errorf("invalid prefix length in subnet CIDR %q: %w", cidr, err)
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(prefixLen, ipv6Bits)}, nil
}
