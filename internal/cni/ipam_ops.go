// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/ipam"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// allocateIPAM allocates a subnet and gateway for the given container. This is
// interface-agnostic — it does not touch any kernel state or network namespaces.
// When enableLocalIPAM is true and no explicit ipam block is configured, falls
// back to a built-in pool allocator using default pool CIDR and subnet length.
func allocateIPAM(args *skel.CmdArgs, pluginConf *PluginConf) (*ipamResult, error) {
	var pool *ipam.PoolAllocator
	var subnet *net.IPNet
	var err error

	// pluginConf.IPAM is nil whenever the CNI config omits the "ipam" block
	// entirely (e.g. tap mode relying solely on --enable-local-ipam); fall
	// back to a zero-value IPAM so field access below is nil-safe.
	var ipamConf IPAM
	if pluginConf.IPAM != nil {
		ipamConf = *pluginConf.IPAM
	}

	// When local IPAM is enabled but no explicit ipam type is configured,
	// use the built-in pool allocator with defaults.
	poolType := ipamConf.Type
	if poolType == "" && enableLocalIPAM {
		poolType = ipamTypePool
	}

	switch poolType {
	case "static":
		alloc := ipam.NewStaticAllocator()
		allocIP, err := alloc.Allocate(args.ContainerID, ipamConf.StaticIP)
		if err != nil {
			return nil, fmt.Errorf("allocate static IP: %w", err)
		}
		subnet = &net.IPNet{
			IP:   allocIP,
			Mask: net.CIDRMask(64, 128),
		}
	case ipamTypePool:
		poolCIDR := ipamConf.Pool
		gateway := ipamConf.Gateway
		subnetLen := ipamConf.SubnetLen
		if poolCIDR == "" && enableLocalIPAM {
			poolCIDR = localIPAMDefaultPool
		}
		if subnetLen == 0 && enableLocalIPAM {
			subnetLen = localIPAMDefaultSubnetLen
		}
		pool, err = ipam.NewPoolAllocator(poolCIDR, gateway, subnetLen)
		if err != nil {
			return nil, fmt.Errorf("create pool allocator: %w", err)
		}
		subnet, err = pool.Allocate(args.ContainerID)
		if err != nil {
			return nil, fmt.Errorf("allocate from pool: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown IPAM type: %s", ipamConf.Type)
	}

	var gateway net.IP
	if pool != nil {
		gateway = pool.Gateway()
	}

	var routes []*net.IPNet
	if gateway != nil {
		defaultRoute := &net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, 128),
		}
		routes = append(routes, defaultRoute)
	}

	slog.Debug("IPAM: allocated", "containerID", args.ContainerID, "type", poolType, "subnet", subnet, "gateway", gateway)

	return &ipamResult{
		subnet:  subnet,
		gateway: gateway,
		routes:  routes,
	}, nil
}

// configureIPAM allocates a subnet and configures the guest interface inside the
// container network namespace. This is veth-only; for tap mode, use allocateIPAM
// directly (the VM manages its own guest interface). When enableLocalIPAM is
// true and no explicit ipam block is configured, falls back to a built-in pool
// allocator using default pool CIDR and subnet length.
func configureIPAM(args *skel.CmdArgs, pluginConf *PluginConf, guestName string) (*ipamResult, error) {
	ipamResult, err := allocateIPAM(args, pluginConf)
	if err != nil {
		return nil, err
	}

	if err := configureInterfaceInNetns(args.Netns, guestName, ipamResult.subnet, ipamResult.gateway); err != nil {
		return nil, err
	}

	return ipamResult, nil
}

// deallocateIPAM releases the IPAM allocation for the given container.
// Reads the allocated subnet from the BGPAdvertisement CRD annotation, then
// deallocates it from the in-memory pool. When enableLocalIPAM is true and
// no explicit ipam block is configured, uses the default pool CIDR.
func deallocateIPAM(args *skel.CmdArgs, pluginConf *PluginConf, k8s client.Client) {
	// Look up the allocated subnet from the BGPAdvertisement annotation.
	subnetCIDR := getAllocatedSubnetFromCRD(args.ContainerID, pluginConf, k8s)
	if subnetCIDR == "" {
		// No allocation found — either allocation was never completed,
		// or the advertisement was already deleted. Nothing to clean up.
		slog.Debug("IPAM: no allocation found to deallocate", "containerID", args.ContainerID)
		return
	}

	var ipamConf IPAM
	if pluginConf.IPAM != nil {
		ipamConf = *pluginConf.IPAM
	}

	ipamType := ipamConf.Type
	if ipamType == "" && enableLocalIPAM {
		ipamType = ipamTypePool
	}

	switch ipamType {
	case ipamTypePool:
		poolCIDR := ipamConf.Pool
		if poolCIDR == "" && enableLocalIPAM {
			poolCIDR = localIPAMDefaultPool
		}
		pa, err := ipam.NewPoolAllocator(poolCIDR, ipamConf.Gateway, ipamConf.SubnetLen)
		if err != nil {
			// Pool creation failed — allocation was never completed, nothing to clean up.
			slog.Warn("IPAM: failed to build pool allocator for deallocation, skipping", "err", err,
				"containerID", args.ContainerID, "subnet", subnetCIDR)
			return
		}
		pa.Deallocate(subnetCIDR)
		slog.Debug("IPAM: deallocated", "containerID", args.ContainerID, "subnet", subnetCIDR)
	case "static":
		// Static allocations don't need deallocation.
	}
}

// getAllocatedSubnetFromCRD reads the allocated subnet for the given container
// from the BGPAdvertisement CRD annotation. Returns empty string if not found.
func getAllocatedSubnetFromCRD(containerID string, pluginConf *PluginConf, k8s client.Client) string {
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
		return ""
	}

	return adv.Annotations[subnetAnnotationKey(containerID)]
}
