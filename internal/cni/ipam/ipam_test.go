// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"net"
	"strconv"
	"testing"
)

const (
	testPoolCIDR  = "fd00:10:ff01::/64"
	testPoolGw    = "fd00:10:ff01::1"
	testSubnetLen = 96
	// testReservedSub is the /96 subnet containing testPoolGw. It is never
	// handed out by Allocate — see TestPoolAllocatorReservesGatewaySubnet.
	testReservedSub = "fd00:10:ff01::/96"
	// testAllocatedSub is the first /96 subnet Allocate actually hands out
	// from testPoolCIDR, once testReservedSub is skipped.
	testAllocatedSub = "fd00:10:ff01::100:0/96"
	// nextSubnet is the second /96 subnet Allocate hands out from
	// testPoolCIDR, used across tests.
	nextSubnet = "fd00:10:ff01::200:0/96"

	// testInvalidCIDR and testInvalidGateway are shared across this
	// package's test files to avoid duplicate string literals.
	testInvalidCIDR    = "not-a-cidr"
	testInvalidGateway = "not-an-ip"
)

func TestNewPoolAllocator(t *testing.T) {
	tests := []struct {
		name      string
		poolCIDR  string
		gateway   string
		subnetLen int
		wantErr   bool
		wantGw    string
		wantLen   int
	}{
		{
			name:      "valid /64 pool with gateway and subnet length",
			poolCIDR:  testPoolCIDR,
			gateway:   testPoolGw,
			subnetLen: testSubnetLen,
			wantGw:    testPoolGw,
			wantLen:   testSubnetLen,
		},
		{
			name:      "valid /48 pool without gateway defaults to .1",
			poolCIDR:  "fd00:10:ff02::/48",
			subnetLen: testSubnetLen,
			wantGw:    "fd00:10:ff02::1",
			wantLen:   testSubnetLen,
		},
		{
			name:     "zero subnet length uses default",
			poolCIDR: "fd00:feed::/48",
			wantGw:   "fd00:feed::1",
			wantLen:  DefaultSubnetLen,
		},
		{
			name:     "rejects IPv4 pool",
			poolCIDR: "10.244.1.0/24",
			wantErr:  true,
		},
		{
			name:     "rejects invalid CIDR",
			poolCIDR: testInvalidCIDR,
			wantErr:  true,
		},
		{
			name:     "rejects gateway outside pool",
			poolCIDR: testPoolCIDR,
			gateway:  "fd00:20::1",
			wantErr:  true,
		},
		{
			name:     "rejects invalid gateway",
			poolCIDR: testPoolCIDR,
			gateway:  testInvalidGateway,
			wantErr:  true,
		},
		{
			name:      "rejects pool longer than subnet length",
			poolCIDR:  "fd00:10:ff01::/80",
			subnetLen: 64,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa, err := NewPoolAllocator(tt.poolCIDR, tt.gateway, tt.subnetLen, t.TempDir())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gw := pa.Gateway()
			if gw == nil {
				t.Fatal("Gateway() returned nil")
			}
			if gw.String() != tt.wantGw {
				t.Errorf("Gateway() = %q, want %q", gw.String(), tt.wantGw)
			}
		})
	}
}

func TestPoolAllocatorAllocate(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		containerID string
		wantSubnet  string
		wantErr     bool
	}{
		{
			name:        "first allocation returns first subnet",
			containerID: "container-1",
			wantSubnet:  testAllocatedSub,
		},
		{
			name:        "second allocation returns next subnet",
			containerID: "container-2",
			wantSubnet:  nextSubnet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnet, err := pa.Allocate(tt.containerID)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if subnet == nil {
				t.Fatal("Allocate returned nil subnet")
			}
			if subnet.String() != tt.wantSubnet {
				t.Errorf("Allocate() = %q, want %q", subnet.String(), tt.wantSubnet)
			}
		})
	}
}

func TestPoolAllocatorSkipsAllocatedSubnets(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First container gets the first allocatable /96 (the gateway's /96 is reserved).
	subnet1, err := pa.Allocate("container-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subnet1.String() != testAllocatedSub {
		t.Errorf("first alloc = %q, want %q", subnet1, testAllocatedSub)
	}

	// Second container should get the next /96, not the first (already taken).
	subnet2, err := pa.Allocate("container-y")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want2 := nextSubnet
	if subnet2.String() != want2 {
		t.Errorf("second alloc = %q, want %q", subnet2, want2)
	}
}

func TestPoolAllocatorReservesGatewaySubnet(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The very first /96 in the pool is the gateway's own subnet
	// (testReservedSub) — the case that matters, since Allocate walks the
	// pool from its start. Confirm it's skipped in favor of the next /96,
	// and re-confirm across a further run of allocations: an endpoint that
	// owned the gateway's /96 could self-assign the gateway's own address
	// to one of its secondary/pod addresses, colliding with the address
	// every other endpoint in the pool routes its default route through.
	const numAllocations = 1000
	for i := range numAllocations {
		subnet, err := pa.Allocate(strconv.Itoa(i))
		if err != nil {
			t.Fatalf("unexpected error on allocation %d: %v", i, err)
		}
		if subnet.String() == testReservedSub {
			t.Fatalf("Allocate() returned reserved gateway subnet %q on allocation %d", testReservedSub, i)
		}
	}

	if pa.IsAllocated(testReservedSub) {
		t.Error("IsAllocated() = true for the reserved gateway subnet, want false")
	}
}

func TestPoolAllocatorDeallocate(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocate a subnet.
	subnet1, err := pa.Allocate("container-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Deallocate it.
	pa.Deallocate(subnet1.String())

	// Allocate again — should get the same subnet back.
	subnet2, err := pa.Allocate("container-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subnet1.String() != subnet2.String() {
		t.Errorf("re-allocated subnet %q != original %q", subnet2, subnet1)
	}
}

func TestPoolAllocatorDeallocateUnknown(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not panic.
	pa.Deallocate("fd00:dead::/80")
}

func TestPoolAllocatorRejectsEmptyLockDir(t *testing.T) {
	if _, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, ""); err == nil {
		t.Fatal("expected error for empty lockDir, got nil")
	}
}

// TestPoolAllocatorPersistsAcrossInstances is the regression test for the
// bug this package's on-disk persistence fixes: each CNI ADD/DEL is a
// separate OS process, so a fresh *PoolAllocator constructed by DEL must
// still see the allocation ADD's own (now-exited) *PoolAllocator made.
func TestPoolAllocatorPersistsAcrossInstances(t *testing.T) {
	lockDir := t.TempDir()

	addPA, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, lockDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	subnet, err := addPA.Allocate("container-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A brand new instance, as DEL's own process would construct, must see
	// the allocation the (conceptually already-exited) ADD process made.
	delPA, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, lockDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !delPA.IsAllocated(subnet.String()) {
		t.Fatalf("IsAllocated(%q) = false on a fresh instance, want true (persisted)", subnet)
	}

	gotSubnet, ok := delPA.DeallocateContainer("container-a")
	if !ok {
		t.Fatal("DeallocateContainer(\"container-a\") = false, want true")
	}
	if gotSubnet != subnet.String() {
		t.Errorf("DeallocateContainer returned %q, want %q", gotSubnet, subnet.String())
	}
	if delPA.IsAllocated(subnet.String()) {
		t.Error("IsAllocated after DeallocateContainer = true, want false")
	}
}

func TestPoolAllocatorDeallocateContainerUnknown(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := pa.DeallocateContainer("no-such-container"); ok {
		t.Error("DeallocateContainer for unknown container = true, want false")
	}
}

func TestPoolAllocatorIsAllocated(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pa.IsAllocated("fd00:dead::/80") {
		t.Error("IsAllocated returned true for unknown subnet")
	}

	if _, err := pa.Allocate("known"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !pa.IsAllocated(testAllocatedSub) {
		t.Error("IsAllocated returned false for known container")
	}

	pa.Deallocate(testAllocatedSub)
	if pa.IsAllocated(testAllocatedSub) {
		t.Error("IsAllocated returned true after deallocate")
	}
}

func TestStaticAllocator(t *testing.T) {
	sa := NewStaticAllocator()

	tests := []struct {
		name        string
		containerID string
		addr        string
		wantIP      string
		wantErr     bool
	}{
		{
			name:        "valid IPv6",
			containerID: "c1",
			addr:        "fd00:10:ff01::5",
			wantIP:      "fd00:10:ff01::5",
		},
		{
			name:        "valid IPv6 full form",
			containerID: "c2",
			addr:        "2001:db8::1",
			wantIP:      "2001:db8::1",
		},
		{
			name:        "rejects IPv4",
			containerID: "c3",
			addr:        "10.244.1.5",
			wantErr:     true,
		},
		{
			name:        "rejects invalid IP",
			containerID: "c4",
			addr:        "not-an-ip",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := sa.Allocate(tt.containerID, tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ip == nil {
				t.Fatal("Allocate returned nil IP")
			}
			if ip.String() != tt.wantIP {
				t.Errorf("Allocate() = %q, want %q", ip.String(), tt.wantIP)
			}
		})
	}
}

func TestIncSubnet(t *testing.T) {
	tests := []struct {
		input     string
		subnetLen int
		output    string
	}{
		// /96 subnets from a /64 pool: each step advances by 2^32.
		{input: "fd00:10:ff01::", subnetLen: 96, output: "fd00:10:ff01::100:0"},
		{input: "fd00:10:ff01:0:0:1::", subnetLen: 96, output: "fd00:10:ff01::1:100:0"},
		{input: "fd00:10:ff01:0:0:ff::", subnetLen: 96, output: "fd00:10:ff01::ff:100:0"},
		{input: "fd00:10:ff00::", subnetLen: 96, output: "fd00:10:ff00::100:0"},
		// /64 subnets (boundary at byte 8).
		{input: "fd00:10::", subnetLen: 64, output: "fd00:10:0:0:100::"},
		// /56 subnets (boundary at byte 7).
		{input: "fd00::", subnetLen: 56, output: "fd00:0:0:1::"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip := net.ParseIP(tt.input)
			incSubnet(ip, tt.subnetLen)
			if ip.String() != tt.output {
				t.Errorf("incSubnet(%q, /%d) = %q, want %q", tt.input, tt.subnetLen, ip.String(), tt.output)
			}
		})
	}
}
