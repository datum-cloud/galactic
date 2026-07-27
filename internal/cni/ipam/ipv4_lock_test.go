// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"fmt"
	"sync"
	"testing"
)

// TestIPv4PoolAllocatorCrossProcessPersistence simulates two separate CNI
// plugin invocations (each ADD is its own OS process) racing to allocate
// from the same shared site-wide IPv4 pool. A second allocator instance
// pointed at the same lockDir must see the first instance's allocation and
// never hand out the same address.
func TestIPv4PoolAllocatorCrossProcessPersistence(t *testing.T) {
	dir := t.TempDir()

	a, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	addr1, err := a.Allocate("container-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	addr2, err := b.Allocate("container-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if addr1.String() == addr2.String() {
		t.Fatalf("second allocator instance re-allocated %q already held by the first", addr1)
	}
}

// TestIPv4PoolAllocatorCrossProcessConcurrency drives concurrent Allocate
// calls from independent allocator instances (simulating concurrent ADDs
// from different VPCs on the same node) against the same pool and lockDir,
// and confirms no address is ever handed out twice.
func TestIPv4PoolAllocatorCrossProcessConcurrency(t *testing.T) {
	dir := t.TempDir()

	// testIPv4PoolCIDR is a /29 with exactly 4 usable addresses.
	const n = 4

	addrs := make([]string, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, dir)
			if err != nil {
				errs[i] = err
				return
			}
			addr, err := a.Allocate(fmt.Sprintf("container-%d", i))
			if err != nil {
				errs[i] = err
				return
			}
			addrs[i] = addr.String()
		}(i)
	}
	wg.Wait()

	seen := make(map[string]int, n)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("allocator %d: unexpected error: %v", i, err)
		}
		seen[addrs[i]]++
	}
	for addr, count := range seen {
		if count > 1 {
			t.Errorf("address %q allocated %d times concurrently, want 1", addr, count)
		}
	}
}

// TestIPv4PoolAllocatorCrossProcessDeallocate confirms a Deallocate from one
// allocator instance frees the address for a subsequent instance pointed at
// the same lockDir, matching the persist-across-processes contract.
func TestIPv4PoolAllocatorCrossProcessDeallocate(t *testing.T) {
	dir := t.TempDir()

	a, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	addr, err := a.Allocate("container-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a.Deallocate(addr.String())

	b, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.IsAllocated(addr.String()) {
		t.Fatalf("address %q still marked allocated after Deallocate", addr)
	}

	reAddr, err := b.Allocate("container-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reAddr.String() != addr.String() {
		t.Errorf("re-allocated address %q != freed address %q", reAddr, addr)
	}
}
