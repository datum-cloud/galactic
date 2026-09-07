// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ipam provides IPv6 subnet allocation for the Galactic CNI. Each
// allocation returns a subnet, a /96 by default, from a larger CIDR pool.
//
// Allocations persist as an on-disk marker file per allocated subnet, keyed by
// the pool CIDR. That is required because each CNI ADD and DEL is a separate
// process: an in-memory record is discarded the moment the ADD that created it
// exits, leaving DEL nothing to look up.
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

	// poolLockFileName is the flock target within each pool's state directory.
	// Every other entry there is an allocation marker named after the subnet it
	// reserves.
	poolLockFileName = "lock"
)

// DefaultLockDir is the node-local parent directory for the on-disk lock and
// allocation state both allocators use to stay correct across separate plugin
// invocations. Each pool's CIDR namespaces its state into its own
// subdirectory, so an IPv6 and an IPv4 pool never collide.
const DefaultLockDir = "/var/lib/cni/galactic-ipam"

// PoolAllocator allocates IPv6 subnets from a CIDR pool, persisting each
// allocation as a marker file under a lock directory and guarding it with a
// cross-process flock.
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

// NewPoolAllocator creates a pool allocator over an IPv6 CIDR pool.
//
// gateway may be empty, in which case the first address in the pool is used.
// subnetLen may be 0, in which case DefaultSubnetLen applies; the pool's own
// prefix must be no longer than it. lockDir is this pool's parent directory for
// on-disk lock and allocation state and must not be empty.
//
// The subnet containing the gateway is reserved and never handed out, since
// otherwise the endpoint owning it could self-assign the gateway's address and
// collide with the address every other endpoint routes its default through.
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

// Allocate assigns the next available IPv6 subnet from the pool to containerID,
// skipping the subnet holding the gateway and any subnet another allocation
// already holds according to the on-disk markers, which is what makes it
// correct across separate plugin invocations.
//
// A containerID that already holds an allocation gets the same subnet back
// rather than a fresh one. The CNI spec permits a runtime to retry ADD for the
// same container after a transient failure, and without that check each retry
// would leak the previous attempt's marker, only one of which is ever
// recoverable on DEL.
//
// Returns the allocated subnet, or an error if the pool is exhausted.
// Thread-safe.
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

// usedSubnets returns the set of subnet CIDR strings currently marked
// allocated. Callers must hold both mu and the pool's flock.
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

// Deallocate removes the allocation for subnetCIDR, ignoring an unknown subnet.
// Serialized like Allocate. A caller that knows only the containerID should use
// DeallocateContainer.
func (a *PoolAllocator) Deallocate(subnetCIDR string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	_ = a.state.withLock(func() error {
		return os.Remove(filepath.Join(a.stateDir, sanitizePoolDirName(subnetCIDR)))
	})
}

// LookupContainer reports the subnet allocated to containerID, without removing
// it, for CHECK to confirm an allocation is still in place. Returns ("", false)
// when none is found.
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

// DeallocateContainer removes the allocation held by containerID without the
// caller needing to know the subnet: the marker records which container holds
// each one, so this is a direct scan of this pool's state with no external
// lookup. The scan and removal share a single flock acquisition, so a
// concurrent process on the same pool cannot interleave between them. Returns
// the deallocated subnet and true, or ("", false).
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

// incSubnet advances ip by one subnet step, in place, the step being
// 2^(128-subnetLen).
//
// Only bytes strictly after the network boundary are zeroed; the boundary byte
// itself keeps counting up across repeated calls on the same IP, which is how
// Allocate walks pool boundaries. Zeroing it on every call resets the counter
// to its just-computed value, so a chained sequence never advances past the
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

// desanitizeMarkerName reverses the "/" to "-" replacement in a subnet marker
// filename. A CIDR carries exactly one "/", so replacing the first "-" is
// unambiguous: subnet strings otherwise contain only hex digits and ":".
func desanitizeMarkerName(name string) string {
	before, after, found := strings.Cut(name, "-")
	if !found {
		return name
	}
	return before + "/" + after
}

// parseAllocatedSubnet parses a subnet CIDR string previously produced by
// Allocate back into a *net.IPNet, preserving its address exactly.
//
// net.ParseCIDR is deliberately not used: it returns the masked network
// address, which zeroes the per-subnet counter byte incSubnet advances, since
// that byte sits inside what a strict mask treats as host bits. Re-masking a
// stored subnet would collapse every allocated subnet in the pool back to the
// same reserved address.
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
