// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import "testing"

const (
	// testIPv4PoolCIDR is a /29 (8 addresses) so tests can exercise
	// exhaustion without thousands of allocations. Reserved addresses:
	// .0 (network), .1 (gateway), .6 (second-to-last), .7 (last/broadcast).
	// Usable: .2, .3, .4, .5.
	testIPv4PoolCIDR = "10.128.0.0/29"
	testIPv4Gw       = "10.128.0.1"
)

func TestNewIPv4PoolAllocator(t *testing.T) {
	tests := []struct {
		name     string
		poolCIDR string
		gateway  string
		wantErr  bool
		wantGw   string
	}{
		{
			name:     "valid /29 pool with explicit gateway",
			poolCIDR: testIPv4PoolCIDR,
			gateway:  testIPv4Gw,
			wantGw:   testIPv4Gw,
		},
		{
			name:     "valid /29 pool without gateway defaults to network+1",
			poolCIDR: "10.128.0.8/29",
			wantGw:   "10.128.0.9",
		},
		{
			name:     "rejects IPv6 pool",
			poolCIDR: "fd00:10:ff01::/64",
			wantErr:  true,
		},
		{
			name:     "rejects invalid CIDR",
			poolCIDR: testInvalidCIDR,
			wantErr:  true,
		},
		{
			name:     "rejects gateway outside pool",
			poolCIDR: testIPv4PoolCIDR,
			gateway:  "10.200.0.1",
			wantErr:  true,
		},
		{
			name:     "rejects invalid gateway",
			poolCIDR: testIPv4PoolCIDR,
			gateway:  testInvalidGateway,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewIPv4PoolAllocator(tt.poolCIDR, tt.gateway, t.TempDir())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gw := a.Gateway()
			if gw == nil {
				t.Fatal("Gateway() returned nil")
			}
			if gw.String() != tt.wantGw {
				t.Errorf("Gateway() = %q, want %q", gw.String(), tt.wantGw)
			}
		})
	}
}

func TestIPv4PoolAllocatorAllocate(t *testing.T) {
	a, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		containerID string
		wantAddr    string
	}{
		{
			name:        "first allocation skips network and gateway",
			containerID: "container-1",
			wantAddr:    "10.128.0.2",
		},
		{
			name:        "second allocation returns next usable address",
			containerID: "container-2",
			wantAddr:    "10.128.0.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := a.Allocate(tt.containerID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addr.String() != tt.wantAddr {
				t.Errorf("Allocate() = %q, want %q", addr.String(), tt.wantAddr)
			}
		})
	}
}

func TestIPv4PoolAllocatorSkipsReservedAddresses(t *testing.T) {
	a, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reserved := map[string]bool{
		"10.128.0.0": true, // network
		"10.128.0.1": true, // gateway
		"10.128.0.6": true, // second-to-last
		"10.128.0.7": true, // last/broadcast
	}

	// Allocate every usable address in the /29 (4 usable: .2-.5) and
	// confirm none of the reserved addresses were ever handed out.
	for i := range 4 {
		addr, err := a.Allocate("container")
		if err != nil {
			t.Fatalf("unexpected error on allocation %d: %v", i, err)
		}
		if reserved[addr.String()] {
			t.Errorf("Allocate() returned reserved address %q", addr.String())
		}
	}
}

func TestIPv4PoolAllocatorExhaustion(t *testing.T) {
	a, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The /29 has exactly 4 usable addresses (.2-.5); the 5th allocation
	// must fail with an exhaustion error.
	for i := range 4 {
		if _, err := a.Allocate("container"); err != nil {
			t.Fatalf("unexpected error on allocation %d: %v", i, err)
		}
	}

	if _, err := a.Allocate("one-too-many"); err == nil {
		t.Fatal("expected pool exhaustion error, got nil")
	}
}

func TestIPv4PoolAllocatorDeallocate(t *testing.T) {
	a, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	addr1, err := a.Allocate("container-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	a.Deallocate(addr1.String())

	addr2, err := a.Allocate("container-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr1.String() != addr2.String() {
		t.Errorf("re-allocated address %q != original %q", addr2, addr1)
	}
}

func TestIPv4PoolAllocatorDeallocateUnknown(t *testing.T) {
	a, err := NewIPv4PoolAllocator(testIPv4PoolCIDR, testIPv4Gw, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not panic.
	a.Deallocate("10.128.0.99")
}
