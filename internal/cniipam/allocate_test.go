// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"fmt"
	"net"
	"os"
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

// TestAllocateHonoursAddressFamilies drives the full ADD path — parseConf
// followed by allocate — for issue #330's repro: both pools configured, but
// address_families restricts this attachment to IPv6 only. Unlike the other
// tests in this file, which construct *IPAM literals directly and so bypass
// parseConf's filtering, this is the one test that exercises the config path
// an actual ADD invocation takes.
func TestAllocateHonoursAddressFamilies(t *testing.T) {
	withTempLockDir(t)
	input := confJSON(fmt.Sprintf(
		`"type":%q,"ipv6_subnet":%q,"ipv4_subnet":%q,"address_families":["ipv6"]`,
		testIPAMType, testIPv6PoolDefault, testIPv4Subnet))

	conf, err := parseConf([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	args := &skel.CmdArgs{ContainerID: testContainerID}
	res, err := allocate(args, conf.IPAM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IPv6Subnet == nil {
		t.Error("IPv6Subnet = nil, want an allocated /96")
	}
	if res.IPv4Address != nil {
		t.Errorf("IPv4Address = %v, want nil (address_families excludes ipv4)", res.IPv4Address)
	}
	if len(res.Routes) != 1 {
		t.Errorf("Routes = %v, want exactly one default route (ipv6 only)", res.Routes)
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

const (
	testEndpointIPv6 = "fd20:60:ff03:0:1::/96"
	testGatewayIPv6  = "fd20:60:ff03::1"
	testEndpointIPv4 = "203.0.113.17/32"
	testGatewayIPv4  = "203.0.113.1"
)

func dualStackAddresses() *IPAM {
	return &IPAM{
		Type: testIPAMType,
		Addresses: []Address{
			{Address: testEndpointIPv6, Gateway: testGatewayIPv6},
			{Address: testEndpointIPv4, Gateway: testGatewayIPv4},
		},
	}
}

// TestAllocateAddressesPreservesPrefixLength is the whole point of this path:
// an endpoint block decided upstream as a /96 must stay a /96, where the
// legacy static_ip path forced a /64.
func TestAllocateAddressesPreservesPrefixLength(t *testing.T) {
	withTempLockDir(t)
	res, err := allocate(&skel.CmdArgs{ContainerID: testContainerID}, &IPAM{
		Type:      testIPAMType,
		Addresses: []Address{{Address: testEndpointIPv6, Gateway: testGatewayIPv6}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.IPv6Subnet.String(); got != testEndpointIPv6 {
		t.Errorf("IPv6Subnet = %q, want %q", got, testEndpointIPv6)
	}
	if !res.IPv6Gateway.Equal(net.ParseIP(testGatewayIPv6)) {
		t.Errorf("IPv6Gateway = %v, want %s", res.IPv6Gateway, testGatewayIPv6)
	}
	if res.IPv4Address != nil {
		t.Errorf("IPv4Address = %v, want nil for an IPv6-only addresses config", res.IPv4Address)
	}
	if len(res.Routes) != 1 {
		t.Errorf("Routes = %v, want only the IPv6 default route", res.Routes)
	}
}

func TestAllocateAddressesDualStack(t *testing.T) {
	withTempLockDir(t)
	res, err := allocate(&skel.CmdArgs{ContainerID: testContainerID}, dualStackAddresses())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.IPv6Subnet.String(); got != testEndpointIPv6 {
		t.Errorf("IPv6Subnet = %q, want %q", got, testEndpointIPv6)
	}
	if !res.IPv4Address.Equal(net.ParseIP("203.0.113.17")) {
		t.Errorf("IPv4Address = %v, want 203.0.113.17", res.IPv4Address)
	}
	if !res.IPv4Gateway.Equal(net.ParseIP(testGatewayIPv4)) {
		t.Errorf("IPv4Gateway = %v, want %s", res.IPv4Gateway, testGatewayIPv4)
	}
	if len(res.Routes) != 2 {
		t.Errorf("Routes = %v, want one default route per family", res.Routes)
	}
}

func TestAllocateAddressesIPv4Only(t *testing.T) {
	withTempLockDir(t)
	res, err := allocate(&skel.CmdArgs{ContainerID: testContainerID}, &IPAM{
		Type:      testIPAMType,
		Addresses: []Address{{Address: testEndpointIPv4, Gateway: testGatewayIPv4}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IPv6Subnet != nil {
		t.Errorf("IPv6Subnet = %v, want nil for an IPv4-only addresses config", res.IPv6Subnet)
	}
	if res.IPv4Address == nil || !res.IPv4Address.Equal(net.ParseIP("203.0.113.17")) {
		t.Errorf("IPv4Address = %v, want 203.0.113.17", res.IPv4Address)
	}
}

// TestAllocateAddressesRetriedADDIsIdempotent covers a runtime retrying ADD
// for the same container: nothing is persisted, so every attempt returns the
// same assignment.
func TestAllocateAddressesRetriedADDIsIdempotent(t *testing.T) {
	withTempLockDir(t)
	args := &skel.CmdArgs{ContainerID: testContainerID}
	first, err := allocate(args, dualStackAddresses())
	if err != nil {
		t.Fatalf("first ADD: %v", err)
	}
	second, err := allocate(args, dualStackAddresses())
	if err != nil {
		t.Fatalf("retried ADD: %v", err)
	}
	if first.IPv6Subnet.String() != second.IPv6Subnet.String() || !first.IPv4Address.Equal(second.IPv4Address) {
		t.Errorf("retried ADD returned %v/%v, want the first attempt's %v/%v",
			second.IPv6Subnet, second.IPv4Address, first.IPv6Subnet, first.IPv4Address)
	}
	if entries, err := os.ReadDir(lockDir); err != nil || len(entries) != 0 {
		t.Errorf("lock dir holds %v (err %v), want nothing persisted for pre-decided addresses", entries, err)
	}
}

// TestAddressesDeallocateAndCheckAreNoops matches the static_ip path: nothing
// was allocated, so DEL has nothing to release and CHECK has nothing to
// verify.
func TestAddressesDeallocateAndCheckAreNoops(t *testing.T) {
	withTempLockDir(t)
	conf := dualStackAddresses()
	if _, err := allocate(&skel.CmdArgs{ContainerID: testContainerID}, conf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	deallocate(testContainerID, conf)

	if errs := checkAllocation(testContainerID, conf); len(errs) > 0 {
		t.Errorf("checkAllocation = %v, want nil (nothing is stored to check)", errs)
	}
}

func TestParseAddressesRejectsBadConfigs(t *testing.T) {
	tests := []struct {
		name      string
		addresses []Address
	}{
		{"no prefix length", []Address{{Address: "fd20:60:ff03::5"}}},
		{"unparseable address", []Address{{Address: "not-an-address/96"}}},
		{"IPv4 that is not a /32", []Address{{Address: "203.0.113.0/24"}}},
		{"two IPv6 addresses", []Address{{Address: testEndpointIPv6}, {Address: "fd20:60:ff03:0:2::/96"}}},
		{"two IPv4 addresses", []Address{{Address: testEndpointIPv4}, {Address: "203.0.113.18/32"}}},
		{"gateway of the wrong family", []Address{{Address: testEndpointIPv6, Gateway: testGatewayIPv4}}},
		{"unparseable gateway", []Address{{Address: testEndpointIPv6, Gateway: "nope"}}},
		{"empty", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseAddresses(tt.addresses); err == nil {
				t.Errorf("parseAddresses(%v) = nil error, want a config error", tt.addresses)
			}
		})
	}
}
