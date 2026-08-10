// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"net"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

const (
	testContainerID     = "test-container"
	testIPv6PoolDefault = "fd00:10:ff01::/64"
	testIPv4Subnet      = "10.128.0.0/20"
)

func withTempLockDir(t *testing.T) {
	t.Helper()
	original := lockDir
	lockDir = t.TempDir()
	t.Cleanup(func() { lockDir = original })
}

func TestAllocateStatic(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID}
	conf := &IPAM{Type: testIPAMType, StaticIP: "fd00:10:ff01::1234"}

	res, err := allocate(args, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IPv6Subnet == nil || !res.IPv6Subnet.IP.Equal(net.ParseIP("fd00:10:ff01::1234")) {
		t.Errorf("IPv6Subnet = %v, want fd00:10:ff01::1234", res.IPv6Subnet)
	}
	if res.IPv4Address != nil {
		t.Errorf("IPv4Address = %v, want nil for static IPAM", res.IPv4Address)
	}
}

func TestAllocatePoolDualStack(t *testing.T) {
	withTempLockDir(t)
	args := &skel.CmdArgs{ContainerID: testContainerID}
	conf := &IPAM{Type: testIPAMType, IPv6Subnet: testIPv6PoolDefault, IPv4Subnet: testIPv4Subnet}

	res, err := allocate(args, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IPv6Subnet == nil {
		t.Error("IPv6Subnet = nil, want an allocated /96")
	}
	if res.IPv4Address == nil {
		t.Fatal("IPv4Address = nil, want an allocated /32")
	}
	if len(res.Routes) != 2 {
		t.Errorf("Routes = %v, want one default route per family", res.Routes)
	}
}

func TestAllocatePoolMissingBothSubnetsErrors(t *testing.T) {
	withTempLockDir(t)
	args := &skel.CmdArgs{ContainerID: testContainerID}
	if _, err := allocate(args, &IPAM{Type: testIPAMType}); err == nil {
		t.Fatal("expected error when neither subnet is set, got nil")
	}
}

func TestDeallocateStaticNoop(t *testing.T) {
	// Static allocations persist nothing; deallocate must be a pure no-op
	// (this asserts it doesn't panic touching pool state that was never
	// created).
	deallocate(testContainerID, &IPAM{Type: testIPAMType, StaticIP: "fd00::1"})
}

func TestAllocateDeallocateRoundTripIPv6(t *testing.T) {
	withTempLockDir(t)
	args := &skel.CmdArgs{ContainerID: testContainerID}
	conf := &IPAM{Type: testIPAMType, IPv6Subnet: testIPv6PoolDefault}

	res, err := allocate(args, conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A fresh "DEL process" must be able to look the allocation up and
	// deallocate it, without ever being told the allocated subnet.
	deallocate(testContainerID, conf)

	if errs := checkAllocation(testContainerID, conf); len(errs) == 0 {
		t.Errorf("checkAllocation after deallocate = no errors, want a not-found error (subnet %v)", res.IPv6Subnet)
	}
}

func TestAllocateDeallocateRoundTripIPv4(t *testing.T) {
	withTempLockDir(t)
	args := &skel.CmdArgs{ContainerID: testContainerID}
	conf := &IPAM{Type: testIPAMType, IPv4Subnet: testIPv4Subnet}

	if _, err := allocate(args, conf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if errs := checkAllocation(testContainerID, conf); len(errs) != 0 {
		t.Fatalf("checkAllocation before deallocate = %v, want no errors", errs)
	}

	deallocate(testContainerID, conf)

	if errs := checkAllocation(testContainerID, conf); len(errs) == 0 {
		t.Error("checkAllocation after deallocate = no errors, want a not-found error")
	}
}

func TestCheckAllocationStaticAlwaysPasses(t *testing.T) {
	if errs := checkAllocation(testContainerID, &IPAM{Type: testIPAMType, StaticIP: "fd00::1"}); errs != nil {
		t.Errorf("checkAllocation for static IPAM = %v, want nil (nothing persisted to check)", errs)
	}
}

func TestCheckAllocationUnknownContainer(t *testing.T) {
	withTempLockDir(t)
	conf := &IPAM{Type: testIPAMType, IPv6Subnet: testIPv6PoolDefault, IPv4Subnet: testIPv4Subnet}
	errs := checkAllocation("no-such-container", conf)
	if len(errs) != 2 {
		t.Fatalf("checkAllocation for unknown container = %v, want 2 errors (one per family)", errs)
	}
}
