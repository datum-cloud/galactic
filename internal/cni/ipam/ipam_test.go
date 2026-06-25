// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"net"
	"testing"
)

const (
	testPoolCIDR     = "fd00:10:ff01::/48"
	testPoolGw       = "fd00:10:ff01::1"
	testSubnetLen    = 80
	testAllocatedSub = "fd00:10:ff01::/80"
	// nextSubnet is the second /80 subnet from a /48 pool, used across tests.
	nextSubnet = "fd00:10:ff01::100:0:0/80"
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
			name:      "valid /48 pool with gateway and subnet length",
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
			poolCIDR: "not-a-cidr",
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
			gateway:  "not-an-ip",
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
			pa, err := NewPoolAllocator(tt.poolCIDR, tt.gateway, tt.subnetLen)
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
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen)
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
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First container gets the first /80.
	subnet1, err := pa.Allocate("container-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subnet1.String() != testAllocatedSub {
		t.Errorf("first alloc = %q, want %q", subnet1, testAllocatedSub)
	}

	// Second container should get the next /80, not the first (already taken).
	subnet2, err := pa.Allocate("container-y")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want2 := nextSubnet
	if subnet2.String() != want2 {
		t.Errorf("second alloc = %q, want %q", subnet2, want2)
	}
}

func TestPoolAllocatorDeallocate(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen)
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
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not panic.
	pa.Deallocate("fd00:dead::/80")
}

func TestPoolAllocatorIsAllocated(t *testing.T) {
	pa, err := NewPoolAllocator(testPoolCIDR, testPoolGw, testSubnetLen)
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
		// /80 subnets from a /48 pool: each step advances by 2^48.
		{input: "fd00:10:ff01::", subnetLen: 80, output: "fd00:10:ff01::100:0:0"},
		{input: "fd00:10:ff01:0:1::", subnetLen: 80, output: "fd00:10:ff01:0:1:100::"},
		{input: "fd00:10:ff01:0:ff::", subnetLen: 80, output: "fd00:10:ff01:0:ff:100::"},
		{input: "fd00:10:ff00::", subnetLen: 80, output: "fd00:10:ff00::100:0:0"},
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
