// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import "testing"

func TestNewDualStackAllocator(t *testing.T) {
	tests := []struct {
		name        string
		ipv6Pool    string
		ipv6Gateway string
		ipv4Pool    string
		ipv4Gateway string
		wantErr     bool
		wantIPv4Nil bool
	}{
		{
			name:        "dual-stack pool builds both allocators",
			ipv6Pool:    testPoolCIDR,
			ipv6Gateway: testPoolGw,
			ipv4Pool:    testIPv4PoolCIDR,
			ipv4Gateway: testIPv4Gw,
		},
		{
			name:        "empty ipv4 pool leaves ipv4 allocator nil",
			ipv6Pool:    testPoolCIDR,
			ipv6Gateway: testPoolGw,
			ipv4Pool:    "",
			wantIPv4Nil: true,
		},
		{
			name:     "propagates ipv6 pool error",
			ipv6Pool: testInvalidCIDR,
			wantErr:  true,
		},
		{
			name:     "propagates ipv4 pool error when ipv4 is configured",
			ipv6Pool: testPoolCIDR,
			ipv4Pool: testInvalidCIDR,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewDualStackAllocator(tt.ipv6Pool, tt.ipv6Gateway, tt.ipv4Pool, tt.ipv4Gateway, t.TempDir())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantIPv4Nil && a.ipv4 != nil {
				t.Error("expected nil ipv4 allocator")
			}
			if !tt.wantIPv4Nil && a.ipv4 == nil {
				t.Error("expected non-nil ipv4 allocator")
			}
		})
	}
}

func TestDualStackAllocatorAllocate(t *testing.T) {
	t.Run("combined ipv6+ipv4 allocation returns both", func(t *testing.T) {
		a, err := NewDualStackAllocator(testPoolCIDR, testPoolGw, testIPv4PoolCIDR, testIPv4Gw, t.TempDir())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		res, err := a.Allocate("container-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if res.IPv6Subnet == nil {
			t.Fatal("expected non-nil IPv6Subnet")
		}
		if res.IPv6Subnet.String() != testAllocatedSub {
			t.Errorf("IPv6Subnet = %q, want %q", res.IPv6Subnet.String(), testAllocatedSub)
		}
		if res.IPv6Gateway.String() != testPoolGw {
			t.Errorf("IPv6Gateway = %q, want %q", res.IPv6Gateway.String(), testPoolGw)
		}
		if res.IPv4Address == nil {
			t.Fatal("expected non-nil IPv4Address")
		}
		if res.IPv4Address.String() != "10.128.0.2" {
			t.Errorf("IPv4Address = %q, want %q", res.IPv4Address.String(), "10.128.0.2")
		}
		if res.IPv4Gateway.String() != testIPv4Gw {
			t.Errorf("IPv4Gateway = %q, want %q", res.IPv4Gateway.String(), testIPv4Gw)
		}
	})

	t.Run("ipv4-omitted case returns ipv6 only with nil ipv4 fields", func(t *testing.T) {
		a, err := NewDualStackAllocator(testPoolCIDR, testPoolGw, "", "", t.TempDir())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		res, err := a.Allocate("container-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if res.IPv6Subnet == nil {
			t.Fatal("expected non-nil IPv6Subnet")
		}
		if res.IPv4Address != nil {
			t.Errorf("expected nil IPv4Address, got %q", res.IPv4Address.String())
		}
		if res.IPv4Gateway != nil {
			t.Errorf("expected nil IPv4Gateway, got %q", res.IPv4Gateway.String())
		}
	})

	t.Run("propagates ipv4 allocation error once ipv4 pool is exhausted", func(t *testing.T) {
		// testIPv4PoolCIDR is a /29 with 4 usable addresses; exhaust it via
		// the IPv6 pool's much larger address space so the IPv6 side never
		// errors while the IPv4 side is driven to exhaustion.
		a, err := NewDualStackAllocator(testPoolCIDR, testPoolGw, testIPv4PoolCIDR, testIPv4Gw, t.TempDir())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i := range 4 {
			if _, err := a.Allocate("container"); err != nil {
				t.Fatalf("unexpected error on allocation %d: %v", i, err)
			}
		}

		if _, err := a.Allocate("one-too-many"); err == nil {
			t.Fatal("expected ipv4 pool exhaustion error, got nil")
		}
	})
}
