// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"net"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/cni/crdnames"
	"go.datum.net/galactic/internal/cni/ipam"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testVPC         = "abc"
	testAttachment  = "def"
	testContainerID = "test-container"
	testNamespace   = "galactic-system"
	testIPv4Subnet  = "10.128.0.0/20"
)

var testScheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	return s
}()

func fakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(testScheme).WithObjects(objs...).Build()
}

// ---- WantsIPAM -------------------------------------------------------------

func TestWantsIPAM(t *testing.T) {
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()

	tests := []struct {
		name           string
		cfg            AllocConfig
		enableLocalIPA bool
		want           bool
	}{
		{
			name: "no ipam block, no ipv6_subnet, local IPAM disabled",
			cfg:  AllocConfig{},
			want: false,
		},
		{
			name: "static ipam type opts in regardless of other fields",
			cfg:  AllocConfig{IPAM: &IPAM{Type: TypeStatic}},
			want: true,
		},
		{
			name: "ipv6_subnet set opts in",
			cfg:  AllocConfig{IPv6Subnet: localIPAMDefaultPool},
			want: true,
		},
		{
			name: "ipv4_subnet set opts in",
			cfg:  AllocConfig{IPv4Subnet: testIPv4Subnet},
			want: true,
		},
		{
			name:           "local IPAM enabled opts in even without ipv6_subnet",
			cfg:            AllocConfig{},
			enableLocalIPA: true,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enableLocalIPAM = tt.enableLocalIPA
			if got := WantsIPAM(tt.cfg); got != tt.want {
				t.Errorf("WantsIPAM(%+v) = %v, want %v", tt.cfg, got, tt.want)
			}
		})
	}
}

func TestSetEnableLocalIPAM(t *testing.T) {
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()

	enableLocalIPAM = false
	if enableLocalIPAM {
		t.Error("enableLocalIPAM default = true, want false")
	}

	SetEnableLocalIPAM(true)
	if !enableLocalIPAM {
		t.Error("enableLocalIPAM after SetEnableLocalIPAM(true) = false, want true")
	}

	SetEnableLocalIPAM(false)
	if enableLocalIPAM {
		t.Error("enableLocalIPAM after SetEnableLocalIPAM(false) = true, want false")
	}
}

// ---- Allocate ---------------------------------------------------------

func TestAllocateNoAllocation(t *testing.T) {
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()
	enableLocalIPAM = false

	args := &skel.CmdArgs{ContainerID: testContainerID}
	res, err := Allocate(args, AllocConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Errorf("Allocate() = %+v, want nil (WantsIPAM should have been false)", res)
	}
}

func TestAllocateStatic(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID}
	cfg := AllocConfig{IPAM: &IPAM{Type: TypeStatic, StaticIP: "fd00:10:ff01::1234"}}

	res, err := Allocate(args, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("Allocate() = nil, want a result")
	}
	if res.IPv6Subnet == nil || !res.IPv6Subnet.IP.Equal(net.ParseIP("fd00:10:ff01::1234")) {
		t.Errorf("IPv6Subnet = %v, want fd00:10:ff01::1234", res.IPv6Subnet)
	}
	if res.IPv4Address != nil {
		t.Errorf("IPv4Address = %v, want nil for static IPAM", res.IPv4Address)
	}
}

func TestAllocatePoolIPv6Only(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID}
	cfg := AllocConfig{IPv6Subnet: localIPAMDefaultPool}

	res, err := Allocate(args, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("Allocate() = nil, want a result")
	}
	if res.IPv6Subnet == nil {
		t.Fatal("IPv6Subnet = nil, want an allocated /96")
	}
	if ones, bits := res.IPv6Subnet.Mask.Size(); ones != 96 || bits != 128 {
		t.Errorf("IPv6Subnet mask = /%d, want /96", ones)
	}
	if res.IPv6Gateway == nil {
		t.Error("IPv6Gateway = nil, want the pool's default gateway (::1 of the /64)")
	}
	if res.IPv4Address != nil {
		t.Errorf("IPv4Address = %v, want nil (no ipv4_subnet configured)", res.IPv4Address)
	}
	if len(res.Routes) != 1 {
		t.Errorf("Routes = %v, want exactly one default IPv6 route", res.Routes)
	}
}

func TestAllocatePoolIPv4Only(t *testing.T) {
	origLockDir := ipv4LockDir
	ipv4LockDir = t.TempDir()
	defer func() { ipv4LockDir = origLockDir }()

	args := &skel.CmdArgs{ContainerID: testContainerID}
	cfg := AllocConfig{IPv4Subnet: testIPv4Subnet}

	res, err := Allocate(args, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("Allocate() = nil, want a result")
	}
	if res.IPv6Subnet != nil {
		t.Errorf("IPv6Subnet = %v, want nil (no ipv6_subnet configured)", res.IPv6Subnet)
	}
	if res.IPv4Address == nil {
		t.Fatal("IPv4Address = nil, want an allocated /32")
	}
	if res.IPv4Gateway == nil {
		t.Error("IPv4Gateway = nil, want the pool's default gateway")
	}
	if len(res.Routes) != 1 {
		t.Errorf("Routes = %v, want exactly one default IPv4 route", res.Routes)
	}
}

func TestAllocatePoolDualStack(t *testing.T) {
	origLockDir := ipv4LockDir
	ipv4LockDir = t.TempDir()
	defer func() { ipv4LockDir = origLockDir }()

	args := &skel.CmdArgs{ContainerID: testContainerID}
	cfg := AllocConfig{
		IPv6Subnet: localIPAMDefaultPool,
		IPv4Subnet: testIPv4Subnet,
	}

	res, err := Allocate(args, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("Allocate() = nil, want a result")
	}
	if res.IPv6Subnet == nil {
		t.Error("IPv6Subnet = nil, want an allocated /96")
	}
	if res.IPv4Address == nil {
		t.Fatal("IPv4Address = nil, want an allocated /32")
	}
	if res.IPv4Gateway == nil {
		t.Error("IPv4Gateway = nil, want the pool's default gateway")
	}
	if len(res.Routes) != 2 {
		t.Errorf("Routes = %v, want one default route per family", res.Routes)
	}
}

func TestAllocatePoolMissingBothSubnetsErrors(t *testing.T) {
	original := enableLocalIPAM
	defer func() { enableLocalIPAM = original }()
	enableLocalIPAM = false

	args := &skel.CmdArgs{ContainerID: testContainerID}
	_, err := allocatePool(args, AllocConfig{})
	if err == nil {
		t.Fatal("expected error when both ipv6_subnet and ipv4_subnet are unset and local IPAM is disabled, got nil")
	}
}

// ---- Deallocate ---------------------------------------------------------

func TestDeallocateStaticNoop(t *testing.T) {
	// Static IPAM never wrote a CRD annotation for DEL to look up, and
	// Deallocate must return immediately without attempting a k8s lookup.
	cfg := AllocConfig{
		VPC: testVPC, VPCAttachment: testAttachment,
		IPAM: &IPAM{Type: TypeStatic},
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}
	// A nil client would panic if Deallocate tried to use it; passing nil
	// here asserts the static-type early return happens first.
	Deallocate(args, cfg, nil)
}

func TestDeallocateDualStack(t *testing.T) {
	origLockDir := ipv4LockDir
	ipv4LockDir = t.TempDir()
	defer func() { ipv4LockDir = origLockDir }()

	cfg := AllocConfig{
		VPC: testVPC, VPCAttachment: testAttachment,
		Namespace:  testNamespace,
		IPv6Subnet: localIPAMDefaultPool,
		IPv4Subnet: testIPv4Subnet,
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}

	alloc, err := ipam.NewDualStackAllocator(cfg.IPv6Subnet, "", cfg.IPv4Subnet, "", ipv4LockDir)
	if err != nil {
		t.Fatalf("NewDualStackAllocator: %v", err)
	}
	dsRes, err := alloc.Allocate(args.ContainerID)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	ipv4Pool, err := ipam.NewIPv4PoolAllocator(cfg.IPv4Subnet, "", ipv4LockDir)
	if err != nil {
		t.Fatalf("NewIPv4PoolAllocator: %v", err)
	}
	if !ipv4Pool.IsAllocated(dsRes.IPv4Address.String()) {
		t.Fatalf("setup: IPv4 address %s not marked allocated", dsRes.IPv4Address)
	}

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdnames.BGPAdvertisementName(cfg.VPC, cfg.VPCAttachment),
			Namespace: testNamespace,
			Annotations: map[string]string{
				crdnames.SubnetKeyIPv6(args.ContainerID): dsRes.IPv6Subnet.String(),
				crdnames.SubnetKeyIPv4(args.ContainerID): dsRes.IPv4Address.String(),
			},
		},
	}
	k8s := fakeClient(adv)

	Deallocate(args, cfg, k8s)

	if ipv4Pool.IsAllocated(dsRes.IPv4Address.String()) {
		t.Errorf("IPv4 address %s still marked allocated after Deallocate", dsRes.IPv4Address)
	}
}

func TestDeallocateIPv4Only(t *testing.T) {
	origLockDir := ipv4LockDir
	ipv4LockDir = t.TempDir()
	defer func() { ipv4LockDir = origLockDir }()

	cfg := AllocConfig{
		VPC: testVPC, VPCAttachment: testAttachment,
		Namespace:  testNamespace,
		IPv4Subnet: testIPv4Subnet,
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}

	ipv4Pool, err := ipam.NewIPv4PoolAllocator(cfg.IPv4Subnet, "", ipv4LockDir)
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
			Name:      crdnames.BGPAdvertisementName(cfg.VPC, cfg.VPCAttachment),
			Namespace: testNamespace,
			Annotations: map[string]string{
				// No IPv6 annotation — this is an IPv4-only allocation.
				crdnames.SubnetKeyIPv4(args.ContainerID): ipv4Addr.String(),
			},
		},
	}
	k8s := fakeClient(adv)

	// Must not panic despite no ipv6_subnet in config, and must deallocate
	// the IPv4 address.
	Deallocate(args, cfg, k8s)

	if ipv4Pool.IsAllocated(ipv4Addr.String()) {
		t.Errorf("IPv4 address %s still marked allocated after Deallocate", ipv4Addr)
	}
}

func TestDeallocatePartialAllocationNonFatal(t *testing.T) {
	// A v6-only pod (no IPv4 annotation, e.g. pre-existing or a partial ADD
	// failure) must still have its IPv6 side cleaned up without erroring,
	// and must not attempt to touch a nonexistent IPv4 pool.
	cfg := AllocConfig{
		VPC: testVPC, VPCAttachment: testAttachment,
		Namespace:  testNamespace,
		IPv6Subnet: localIPAMDefaultPool,
		// IPv4Subnet intentionally unset.
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdnames.BGPAdvertisementName(cfg.VPC, cfg.VPCAttachment),
			Namespace: testNamespace,
			Annotations: map[string]string{
				crdnames.SubnetKeyIPv6(args.ContainerID): "fd00:10:ff01::1234/96",
			},
		},
	}
	k8s := fakeClient(adv)

	// Must not panic despite no ipv4_subnet in config.
	Deallocate(args, cfg, k8s)
}

func TestDeallocateNoAllocationFound(t *testing.T) {
	cfg := AllocConfig{
		VPC: testVPC, VPCAttachment: testAttachment,
		Namespace: testNamespace,
	}
	args := &skel.CmdArgs{ContainerID: testContainerID}
	// No BGPAdvertisement exists at all.
	k8s := fakeClient()

	// Must return cleanly with nothing to deallocate.
	Deallocate(args, cfg, k8s)
}
