// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"net"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.datum.net/galactic/internal/cni/ipam"
	"go.datum.net/galactic/internal/config"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ---- wantsIPAM ------------------------------------------------------------

func TestWantsIPAM(t *testing.T) {
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()

	tests := []struct {
		name           string
		pluginConf     *PluginConf
		enableLocalIPA bool
		want           bool
	}{
		{
			name:       "no ipam block, no ipv6_subnet, local IPAM disabled",
			pluginConf: &PluginConf{},
			want:       false,
		},
		{
			name:       "static ipam type opts in regardless of other fields",
			pluginConf: &PluginConf{IPAM: &IPAM{Type: ipamTypeStatic}},
			want:       true,
		},
		{
			name:       "ipv6_subnet set opts in",
			pluginConf: &PluginConf{IPv6Subnet: localIPAMDefaultPool},
			want:       true,
		},
		{
			name:       "ipv4_subnet set opts in",
			pluginConf: &PluginConf{IPv4Subnet: testIPv4Subnet},
			want:       true,
		},
		{
			name:           "local IPAM enabled opts in even without ipv6_subnet",
			pluginConf:     &PluginConf{},
			enableLocalIPA: true,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enableLocalIPAM = tt.enableLocalIPA
			if got := wantsIPAM(tt.pluginConf); got != tt.want {
				t.Errorf("wantsIPAM(%+v) = %v, want %v", tt.pluginConf, got, tt.want)
			}
		})
	}
}

// ---- allocateIPAM ----------------------------------------------------------

func TestAllocateIPAMNoAllocation(t *testing.T) {
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()
	enableLocalIPAM = false

	args := &skel.CmdArgs{ContainerID: testContainerID}
	res, err := allocateIPAM(args, &PluginConf{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Errorf("allocateIPAM() = %+v, want nil (wantsIPAM should have been false)", res)
	}
}

func TestAllocateIPAMStatic(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID}
	pluginConf := &PluginConf{
		IPAM: &IPAM{Type: ipamTypeStatic, StaticIP: "fd00:10:ff01::1234"},
	}

	res, err := allocateIPAM(args, pluginConf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("allocateIPAM() = nil, want a result")
	}
	if res.ipv6Subnet == nil || !res.ipv6Subnet.IP.Equal(net.ParseIP("fd00:10:ff01::1234")) {
		t.Errorf("ipv6Subnet = %v, want fd00:10:ff01::1234", res.ipv6Subnet)
	}
	if res.ipv4Address != nil {
		t.Errorf("ipv4Address = %v, want nil for static IPAM", res.ipv4Address)
	}
}

func TestAllocateIPAMPoolIPv6Only(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID}
	pluginConf := &PluginConf{IPv6Subnet: localIPAMDefaultPool}

	res, err := allocateIPAM(args, pluginConf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("allocateIPAM() = nil, want a result")
	}
	if res.ipv6Subnet == nil {
		t.Fatal("ipv6Subnet = nil, want an allocated /96")
	}
	if ones, bits := res.ipv6Subnet.Mask.Size(); ones != 96 || bits != 128 {
		t.Errorf("ipv6Subnet mask = /%d, want /96", ones)
	}
	if res.ipv6Gateway == nil {
		t.Error("ipv6Gateway = nil, want the pool's default gateway (::1 of the /64)")
	}
	if res.ipv4Address != nil {
		t.Errorf("ipv4Address = %v, want nil (no ipv4_subnet configured)", res.ipv4Address)
	}
	if len(res.routes) != 1 {
		t.Errorf("routes = %v, want exactly one default IPv6 route", res.routes)
	}
}

func TestAllocateIPAMPoolIPv4Only(t *testing.T) {
	origLockDir := ipv4LockDir
	ipv4LockDir = t.TempDir()
	defer func() { ipv4LockDir = origLockDir }()

	args := &skel.CmdArgs{ContainerID: testContainerID}
	pluginConf := &PluginConf{IPv4Subnet: testIPv4Subnet}

	res, err := allocateIPAM(args, pluginConf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("allocateIPAM() = nil, want a result")
	}
	if res.ipv6Subnet != nil {
		t.Errorf("ipv6Subnet = %v, want nil (no ipv6_subnet configured)", res.ipv6Subnet)
	}
	if res.ipv4Address == nil {
		t.Fatal("ipv4Address = nil, want an allocated /32")
	}
	if res.ipv4Gateway == nil {
		t.Error("ipv4Gateway = nil, want the pool's default gateway")
	}
	if len(res.routes) != 1 {
		t.Errorf("routes = %v, want exactly one default IPv4 route", res.routes)
	}
}

func TestAllocateIPAMPoolDualStack(t *testing.T) {
	origLockDir := ipv4LockDir
	ipv4LockDir = t.TempDir()
	defer func() { ipv4LockDir = origLockDir }()

	args := &skel.CmdArgs{ContainerID: testContainerID}
	pluginConf := &PluginConf{
		IPv6Subnet: localIPAMDefaultPool,
		IPv4Subnet: testIPv4Subnet,
	}

	res, err := allocateIPAM(args, pluginConf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("allocateIPAM() = nil, want a result")
	}
	if res.ipv6Subnet == nil {
		t.Error("ipv6Subnet = nil, want an allocated /96")
	}
	if res.ipv4Address == nil {
		t.Fatal("ipv4Address = nil, want an allocated /32")
	}
	if res.ipv4Gateway == nil {
		t.Error("ipv4Gateway = nil, want the pool's default gateway")
	}
	if len(res.routes) != 2 {
		t.Errorf("routes = %v, want one default route per family", res.routes)
	}
}

func TestAllocateIPAMPoolMissingBothSubnetsErrors(t *testing.T) {
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()
	enableLocalIPAM = false

	// wantsIPAM only opts in here via the static/ipv6_subnet/ipv4_subnet/
	// local-IPAM signals, so force the pool path directly to exercise the
	// "no source for any pool CIDR" error without relying on wantsIPAM's
	// gating.
	args := &skel.CmdArgs{ContainerID: testContainerID}
	_, err := allocatePoolIPAM(args, &PluginConf{})
	if err == nil {
		t.Fatal("expected error when both ipv6_subnet and ipv4_subnet are unset and local IPAM is disabled, got nil")
	}
}

// ---- deallocateIPAM ---------------------------------------------------------

func TestDeallocateIPAMStaticNoop(t *testing.T) {
	// Static IPAM never wrote a CRD annotation for cmdDel to look up, and
	// deallocateIPAM must return immediately without attempting a k8s lookup.
	pluginConf := &PluginConf{
		VPC: testVPC, VPCAttachment: testAttachment,
		IPAM: &IPAM{Type: ipamTypeStatic},
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}
	// A nil client would panic if deallocateIPAM tried to use it; passing nil
	// here asserts the static-type early return happens first.
	deallocateIPAM(args, pluginConf, nil)
}

func TestDeallocateIPAMDualStack(t *testing.T) {
	origLockDir := ipv4LockDir
	ipv4LockDir = t.TempDir()
	defer func() { ipv4LockDir = origLockDir }()

	pluginConf := &PluginConf{
		VPC: testVPC, VPCAttachment: testAttachment,
		IPv6Subnet: localIPAMDefaultPool,
		IPv4Subnet: testIPv4Subnet,
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}

	// Allocate an IPv4 address the same way ADD would, so there's a real
	// marker file for Deallocate to remove.
	alloc, err := ipam.NewDualStackAllocator(pluginConf.IPv6Subnet, "", pluginConf.IPv4Subnet, "", ipv4LockDir)
	if err != nil {
		t.Fatalf("NewDualStackAllocator: %v", err)
	}
	dsRes, err := alloc.Allocate(args.ContainerID)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	ipv4Pool, err := ipam.NewIPv4PoolAllocator(pluginConf.IPv4Subnet, "", ipv4LockDir)
	if err != nil {
		t.Fatalf("NewIPv4PoolAllocator: %v", err)
	}
	if !ipv4Pool.IsAllocated(dsRes.IPv4Address.String()) {
		t.Fatalf("setup: IPv4 address %s not marked allocated", dsRes.IPv4Address)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
			Namespace: config.DefaultNamespace,
			Annotations: map[string]string{
				subnetAnnotationKeyIPv6(args.ContainerID): dsRes.IPv6Subnet.String(),
				subnetAnnotationKeyIPv4(args.ContainerID): dsRes.IPv4Address.String(),
			},
		},
	}
	pluginConf.Namespace = config.DefaultNamespace
	k8s := fakeClient(adv)

	deallocateIPAM(args, pluginConf, k8s)

	if ipv4Pool.IsAllocated(dsRes.IPv4Address.String()) {
		t.Errorf("IPv4 address %s still marked allocated after deallocateIPAM", dsRes.IPv4Address)
	}
}

func TestDeallocateIPAMIPv4Only(t *testing.T) {
	origLockDir := ipv4LockDir
	ipv4LockDir = t.TempDir()
	defer func() { ipv4LockDir = origLockDir }()

	pluginConf := &PluginConf{
		VPC: testVPC, VPCAttachment: testAttachment,
		Namespace:  config.DefaultNamespace,
		IPv4Subnet: testIPv4Subnet,
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}

	ipv4Pool, err := ipam.NewIPv4PoolAllocator(pluginConf.IPv4Subnet, "", ipv4LockDir)
	if err != nil {
		t.Fatalf("NewIPv4PoolAllocator: %v", err)
	}
	ipv4Addr, err := ipv4Pool.Allocate(args.ContainerID)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if !ipv4Pool.IsAllocated(ipv4Addr.String()) {
		t.Fatalf("setup: IPv4 address %s not marked allocated", ipv4Addr)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
			Namespace: config.DefaultNamespace,
			Annotations: map[string]string{
				// No IPv6 annotation — this is an IPv4-only allocation.
				subnetAnnotationKeyIPv4(args.ContainerID): ipv4Addr.String(),
			},
		},
	}
	k8s := fakeClient(adv)

	// Must not panic despite no ipv6_subnet in config, and must deallocate
	// the IPv4 address.
	deallocateIPAM(args, pluginConf, k8s)

	if ipv4Pool.IsAllocated(ipv4Addr.String()) {
		t.Errorf("IPv4 address %s still marked allocated after deallocateIPAM", ipv4Addr)
	}
}

func TestDeallocateIPAMPartialAllocationNonFatal(t *testing.T) {
	// A v6-only pod (no IPv4 annotation, e.g. pre-existing or a partial ADD
	// failure) must still have its IPv6 side cleaned up without erroring,
	// and must not attempt to touch a nonexistent IPv4 pool.
	pluginConf := &PluginConf{
		VPC: testVPC, VPCAttachment: testAttachment,
		Namespace:  config.DefaultNamespace,
		IPv6Subnet: localIPAMDefaultPool,
		// IPv4Subnet intentionally unset.
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
			Namespace: config.DefaultNamespace,
			Annotations: map[string]string{
				subnetAnnotationKeyIPv6(args.ContainerID): "fd00:10:ff01::1234/96",
			},
		},
	}
	k8s := fakeClient(adv)

	// Must not panic despite no ipv4_subnet in config.
	deallocateIPAM(args, pluginConf, k8s)
}

func TestDeallocateIPAMNoAllocationFound(t *testing.T) {
	pluginConf := &PluginConf{
		VPC: testVPC, VPCAttachment: testAttachment,
		Namespace: config.DefaultNamespace,
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}
	// No BGPAdvertisement exists at all.
	k8s := fakeClient()

	// Must return cleanly with nothing to deallocate.
	deallocateIPAM(args, pluginConf, k8s)
}
