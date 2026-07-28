// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/ipam"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ipv4LockDir is the IPv4PoolAllocator lock/state directory used by
// allocatePoolIPAM/deallocateIPAM. Overridable in tests (mirrors the
// ConfFile pattern in config.go) so unit tests never touch the real
// production path.
var ipv4LockDir = ipam.DefaultIPv4LockDir

// wantsIPAM reports whether the given config should trigger IPAM allocation
// at all. Four independent signals opt in: an explicit "static" IPAM type, a
// configured IPv6Subnet or IPv4Subnet (the NAD-driven pool-IPAM path, either
// family alone or both), or the --enable-local-ipam dev fallback. A config
// with none of these (e.g. a tap workload that manages its own addressing)
// allocates nothing, matching today's behavior of skipping IPAM entirely
// rather than erroring.
func wantsIPAM(pluginConf *PluginConf) bool {
	if pluginConf.IPAM != nil && pluginConf.IPAM.Type == ipamTypeStatic {
		return true
	}
	return pluginConf.IPv6Subnet != "" || pluginConf.IPv4Subnet != "" || enableLocalIPAM
}

// allocateIPAM allocates addresses for the given container. This is
// interface-agnostic — it does not touch any kernel state or network
// namespaces. Returns (nil, nil) when wantsIPAM reports no allocation is
// requested. When enableLocalIPAM is true and IPv6Subnet is unset, falls back
// to a built-in default IPv6 pool CIDR.
func allocateIPAM(args *skel.CmdArgs, pluginConf *PluginConf) (*ipamResult, error) {
	if !wantsIPAM(pluginConf) {
		return nil, nil
	}

	if pluginConf.IPAM != nil && pluginConf.IPAM.Type == ipamTypeStatic {
		return allocateStaticIPAM(args, pluginConf.IPAM)
	}

	return allocatePoolIPAM(args, pluginConf)
}

// allocateStaticIPAM validates and returns the pre-assigned static IPv6
// address from the "static" IPAM block. No IPv4 address is ever allocated
// for static IPAM — it is a single fixed address, not a dual-stack pool.
func allocateStaticIPAM(args *skel.CmdArgs, ipamConf *IPAM) (*ipamResult, error) {
	alloc := ipam.NewStaticAllocator()
	allocIP, err := alloc.Allocate(args.ContainerID, ipamConf.StaticIP)
	if err != nil {
		return nil, fmt.Errorf("allocate static IP: %w", err)
	}
	subnet := &net.IPNet{
		IP:   allocIP,
		Mask: net.CIDRMask(64, 128),
	}
	slog.Debug("IPAM: allocated static", "containerID", args.ContainerID, "subnet", subnet)
	return &ipamResult{ipv6Subnet: subnet}, nil
}

// allocatePoolIPAM allocates a dual-stack, IPv6-only, or IPv4-only pool-based
// endpoint address for the given container, via ipam.DualStackAllocator.
// IPv6Subnet and IPv4Subnet each independently supply a pool CIDR for their
// family; at least one must be set (falling back to localIPAMDefaultPool for
// IPv6 when enableLocalIPAM and both are unset).
func allocatePoolIPAM(args *skel.CmdArgs, pluginConf *PluginConf) (*ipamResult, error) {
	ipv6Pool := pluginConf.IPv6Subnet
	if ipv6Pool == "" && pluginConf.IPv4Subnet == "" {
		if !enableLocalIPAM {
			return nil, errors.New("ipv6_subnet or ipv4_subnet is required (or enable local IPAM)")
		}
		ipv6Pool = localIPAMDefaultPool
	}

	alloc, err := ipam.NewDualStackAllocator(ipv6Pool, "", pluginConf.IPv4Subnet, "", ipv4LockDir)
	if err != nil {
		return nil, fmt.Errorf("create dual-stack allocator: %w", err)
	}

	res, err := alloc.Allocate(args.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("allocate dual-stack addresses: %w", err)
	}

	var routes []*net.IPNet
	if res.IPv6Subnet != nil {
		routes = append(routes, &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)})
	}
	if res.IPv4Address != nil {
		routes = append(routes, &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)})
	}

	slog.Debug("IPAM: allocated", "containerID", args.ContainerID,
		"ipv6Subnet", res.IPv6Subnet, "ipv6Gateway", res.IPv6Gateway,
		"ipv4Address", res.IPv4Address, "ipv4Gateway", res.IPv4Gateway)

	return &ipamResult{
		ipv6Subnet:  res.IPv6Subnet,
		ipv6Gateway: res.IPv6Gateway,
		ipv4Address: res.IPv4Address,
		ipv4Gateway: res.IPv4Gateway,
		routes:      routes,
	}, nil
}

// configureIPAM allocates addresses and configures the guest interface inside
// the container network namespace with both families (when dual-stack). This
// is veth-only; for tap mode, use allocateIPAM directly (the VM manages its
// own guest interface).
func configureIPAM(args *skel.CmdArgs, pluginConf *PluginConf, guestName string) (*ipamResult, error) {
	ipamResult, err := allocateIPAM(args, pluginConf)
	if err != nil {
		return nil, err
	}
	if ipamResult == nil {
		return nil, nil
	}

	var ipv4Net *net.IPNet
	if ipamResult.ipv4Address != nil {
		ipv4Net = &net.IPNet{IP: ipamResult.ipv4Address, Mask: net.CIDRMask(32, 32)}
	}
	if err := configureInterfaceInNetns(
		args.Netns, guestName,
		ipamResult.ipv6Subnet, ipamResult.ipv6Gateway,
		ipv4Net, ipamResult.ipv4Gateway,
	); err != nil {
		return nil, err
	}

	return ipamResult, nil
}

// deallocateIPAM releases the IPAM allocation for the given container.
// Reads the allocated IPv6 subnet and (if present) IPv4 address from the
// BGPAdvertisement CRD annotations, then deallocates each independently and
// non-fatally: a missing annotation for one family (e.g. a pre-existing
// v6-only pod, or a partial ADD failure that never reached IPv4 allocation)
// must not prevent cleanup of the other.
func deallocateIPAM(args *skel.CmdArgs, pluginConf *PluginConf, k8s client.Client) {
	if pluginConf.IPAM != nil && pluginConf.IPAM.Type == ipamTypeStatic {
		// Static allocations don't need deallocation.
		return
	}

	ipv6Subnet, ipv4Addr := getAllocatedSubnetsFromCRD(args.ContainerID, pluginConf, k8s)
	if ipv6Subnet == "" && ipv4Addr == "" {
		// No allocation found — either allocation was never completed,
		// or the advertisement was already deleted. Nothing to clean up.
		slog.Debug("IPAM: no allocation found to deallocate", "containerID", args.ContainerID)
		return
	}

	if ipv6Subnet != "" {
		ipv6Pool := pluginConf.IPv6Subnet
		if ipv6Pool == "" && enableLocalIPAM {
			ipv6Pool = localIPAMDefaultPool
		}
		pa, err := ipam.NewPoolAllocator(ipv6Pool, "", 0)
		if err != nil {
			slog.Warn("IPAM: failed to build IPv6 pool allocator for deallocation, skipping", "err", err,
				"containerID", args.ContainerID, "subnet", ipv6Subnet)
		} else {
			pa.Deallocate(ipv6Subnet)
			slog.Debug("IPAM: deallocated IPv6", "containerID", args.ContainerID, "subnet", ipv6Subnet)
		}
	}

	if ipv4Addr != "" {
		if pluginConf.IPv4Subnet == "" {
			slog.Warn("IPAM: found allocated IPv4 address but no ipv4_subnet in config, skipping deallocation",
				"containerID", args.ContainerID, "address", ipv4Addr)
		} else if pa, err := ipam.NewIPv4PoolAllocator(pluginConf.IPv4Subnet, "", ipv4LockDir); err != nil {
			slog.Warn("IPAM: failed to build IPv4 pool allocator for deallocation, skipping", "err", err,
				"containerID", args.ContainerID, "address", ipv4Addr)
		} else {
			pa.Deallocate(ipv4Addr)
			slog.Debug("IPAM: deallocated IPv4", "containerID", args.ContainerID, "address", ipv4Addr)
		}
	}
}

// getAllocatedSubnetsFromCRD reads the allocated IPv6 subnet and (if present)
// IPv4 address for the given container from the BGPAdvertisement CRD
// annotations. Either return value is empty when not found.
func getAllocatedSubnetsFromCRD(
	containerID string, pluginConf *PluginConf, k8s client.Client,
) (ipv6Subnet, ipv4Addr string) {
	namespace := pluginConf.Namespace

	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bgpAdvertisementName(pluginConf.VPC, pluginConf.VPCAttachment),
			Namespace: namespace,
		},
	}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(adv), adv); err != nil {
		return "", ""
	}

	return adv.Annotations[subnetAnnotationKeyIPv6(containerID)], adv.Annotations[subnetAnnotationKeyIPv4(containerID)]
}
