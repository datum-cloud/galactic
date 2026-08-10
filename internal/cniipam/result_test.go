// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"net"
	"testing"

	type100 "github.com/containernetworking/cni/pkg/types/100"
)

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return ipnet
}

func TestBuildCNIResultNil(t *testing.T) {
	result := BuildCNIResult(testCNIVersion, nil)
	if result.CNIVersion != testCNIVersion {
		t.Errorf("CNIVersion = %q, want %q", result.CNIVersion, testCNIVersion)
	}
	if len(result.IPs) != 0 {
		t.Errorf("IPs = %v, want empty", result.IPs)
	}
}

func TestBuildCNIResultDualStack(t *testing.T) {
	subnet := mustParseCIDR(t, "fd00:10:ff01::1234/96")
	gw6 := net.ParseIP("fd00:10:ff01::1")
	addr4 := net.ParseIP("10.128.0.5")
	gw4 := net.ParseIP("10.128.0.1")
	route6 := mustParseCIDR(t, "::/0")

	result := BuildCNIResult(testCNIVersion, &IPAMResult{
		IPv6Subnet: subnet, IPv6Gateway: gw6,
		IPv4Address: addr4, IPv4Gateway: gw4,
		Routes: []*net.IPNet{route6},
	})

	if len(result.IPs) != 2 {
		t.Fatalf("IPs count = %d, want 2", len(result.IPs))
	}
	if result.IPs[0].Address.String() != subnet.String() {
		t.Errorf("IPs[0].Address = %v, want %v", result.IPs[0].Address, subnet)
	}
	if !result.IPs[0].Gateway.Equal(gw6) {
		t.Errorf("IPs[0].Gateway = %v, want %v", result.IPs[0].Gateway, gw6)
	}
	wantMask := net.CIDRMask(32, 32).String()
	if result.IPs[1].Address.IP.String() != addr4.String() || result.IPs[1].Address.Mask.String() != wantMask {
		t.Errorf("IPs[1].Address = %v, want %s/32", result.IPs[1].Address, addr4)
	}
	if len(result.Routes) != 1 {
		t.Errorf("Routes count = %d, want 1", len(result.Routes))
	}
	// No interfaces should ever be set — that's the master plugin's job.
	if len(result.Interfaces) != 0 {
		t.Errorf("Interfaces = %v, want empty (IPAM delegation never returns interfaces)", result.Interfaces)
	}
}

func TestResultToIPAMResultRoundTrip(t *testing.T) {
	subnet := mustParseCIDR(t, "fd00:10:ff01::1234/96")
	gw6 := net.ParseIP("fd00:10:ff01::1")
	addr4 := net.ParseIP("10.128.0.5")
	gw4 := net.ParseIP("10.128.0.1")
	route6 := mustParseCIDR(t, "::/0")

	built := BuildCNIResult(testCNIVersion, &IPAMResult{
		IPv6Subnet: subnet, IPv6Gateway: gw6,
		IPv4Address: addr4, IPv4Gateway: gw4,
		Routes: []*net.IPNet{route6},
	})

	roundTripped, err := ResultToIPAMResult(built)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if roundTripped.IPv6Subnet == nil || roundTripped.IPv6Subnet.String() != subnet.String() {
		t.Errorf("IPv6Subnet = %v, want %v", roundTripped.IPv6Subnet, subnet)
	}
	if !roundTripped.IPv6Gateway.Equal(gw6) {
		t.Errorf("IPv6Gateway = %v, want %v", roundTripped.IPv6Gateway, gw6)
	}
	if roundTripped.IPv4Address == nil || !roundTripped.IPv4Address.Equal(addr4) {
		t.Errorf("IPv4Address = %v, want %v", roundTripped.IPv4Address, addr4)
	}
	if !roundTripped.IPv4Gateway.Equal(gw4) {
		t.Errorf("IPv4Gateway = %v, want %v", roundTripped.IPv4Gateway, gw4)
	}
	if len(roundTripped.Routes) != 1 {
		t.Fatalf("Routes count = %d, want 1", len(roundTripped.Routes))
	}
}

func TestResultToIPAMResultEmpty(t *testing.T) {
	empty := &type100.Result{CNIVersion: testCNIVersion}
	res, err := ResultToIPAMResult(empty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IPv6Subnet != nil || res.IPv4Address != nil {
		t.Errorf("res = %+v, want all-nil fields", res)
	}
}
