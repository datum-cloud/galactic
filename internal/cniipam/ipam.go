// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cniipam holds the IPAM allocation/deallocation logic shared by
// every master plugin in the galactic CNI chain (galactic-cni, veth;
// galactic-tap-cni, tap) — interface-agnostic, since neither kernel state
// nor network namespaces are touched here (galactic-cni's own
// configureInterfaceInNetns applies the result to the guest veth; tap mode
// applies nothing, the VM manages its own interface).
//
// This package is a plain library today, imported directly by the master
// plugins, not yet a delegated CNI IPAM plugin of its own — that lands in a
// follow-up step (cmd/galactic-ipam, the CNI IPAM delegation protocol, and
// dropping the getAllocatedSubnetsFromCRD dependency below in favor of local
// marker-file persistence for the IPv6 pool allocator, mirroring
// IPv4PoolAllocator's). Landing this as its own package now — instead of
// duplicating it between galactic-cni and galactic-tap-cni — means that
// follow-up step only has to add the delegation wiring, not first
// de-duplicate two drifted copies.
package cniipam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/cni/crdnames"
	"go.datum.net/galactic/internal/cni/ipam"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// cniTimeout bounds the k8s API call getAllocatedSubnetsFromCRD makes while
// deallocating. Mirrors internal/cni's own cniTimeout — small enough that a
// duplicated constant beats a shared package for this alone.
const cniTimeout = 10 * time.Second

// TypeStatic is the ipam.type value for a single pre-assigned static
// address. Any other (or empty) value takes the pool-based dual-stack path
// — see WantsIPAM/Allocate.
const TypeStatic = "static"

// localIPAMDefaultPool is the IPv6 CIDR pool used when local IPAM is enabled
// but IPv6Subnet is unset in the CNI config. Allocations from it use
// ipam.DefaultSubnetLen (/96).
const localIPAMDefaultPool = "fd00:10:ff01::/64"

// IPAM holds IP address management configuration passed in the CNI config's
// "ipam" block.
type IPAM struct {
	Type      string    `json:"type"`                // "pool" (default) or "static"
	StaticIP  string    `json:"static_ip,omitempty"` // used when type="static"
	Routes    []Route   `json:"routes,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
}

// Route describes a static route to install.
type Route struct {
	Dst string `json:"dst"`
	GW  string `json:"gw,omitempty"`
}

// Address describes a static IP address assignment.
type Address struct {
	Address string `json:"address"`
}

// IPAMResult holds the IPAM allocation details a caller uses to build its
// own CNI result and, for veth, to configure the guest interface.
// IPv4Address/IPv4Gateway are nil when the attachment is IPv6-only.
type IPAMResult struct {
	IPv6Subnet  *net.IPNet
	IPv6Gateway net.IP
	IPv4Address net.IP
	IPv4Gateway net.IP
	Routes      []*net.IPNet
}

// AllocConfig carries the subset of a caller's own CNI config that IPAM
// allocation needs. Each master plugin passes its own values in — this
// package doesn't know, or need to know, about the rest of that config's
// shape.
type AllocConfig struct {
	VPC             string
	VPCAttachment   string
	Namespace       string
	IPAM            *IPAM
	IPv6Subnet      string
	IPv4Subnet      string
	AddressFamilies []string
}

// ipv4LockDir is the IPv4PoolAllocator lock/state directory used by
// allocatePoolIPAM/Deallocate. Overridable in tests so unit tests never
// touch the real production path.
var ipv4LockDir = ipam.DefaultIPv4LockDir

// enableLocalIPAM controls whether allocation proceeds when no explicit
// "ipam" block is present in the CNI config. Defaults to false.
var enableLocalIPAM bool

// SetEnableLocalIPAM sets the local IPAM flag from the CLI/env.
func SetEnableLocalIPAM(v bool) {
	enableLocalIPAM = v
}

// WantsIPAM reports whether cfg should trigger IPAM allocation at all. Four
// independent signals opt in: an explicit "static" IPAM type, a configured
// IPv6Subnet or IPv4Subnet (the NAD-driven pool-IPAM path, either family
// alone or both), or the enable-local-ipam dev fallback. A config with none
// of these (e.g. a tap workload that manages its own addressing) allocates
// nothing, matching the CNI plugin's own longstanding behavior of skipping
// IPAM entirely rather than erroring.
func WantsIPAM(cfg AllocConfig) bool {
	if cfg.IPAM != nil && cfg.IPAM.Type == TypeStatic {
		return true
	}
	return cfg.IPv6Subnet != "" || cfg.IPv4Subnet != "" || enableLocalIPAM
}

// Allocate allocates addresses for the given container. This is
// interface-agnostic — it does not touch any kernel state or network
// namespaces. Returns (nil, nil) when WantsIPAM reports no allocation is
// requested. When enableLocalIPAM is true and IPv6Subnet is unset, falls
// back to a built-in default IPv6 pool CIDR.
func Allocate(args *skel.CmdArgs, cfg AllocConfig) (*IPAMResult, error) {
	if !WantsIPAM(cfg) {
		return nil, nil
	}

	if cfg.IPAM != nil && cfg.IPAM.Type == TypeStatic {
		return allocateStatic(args, cfg.IPAM)
	}

	return allocatePool(args, cfg)
}

// allocateStatic validates and returns the pre-assigned static IPv6 address
// from the "static" IPAM block. No IPv4 address is ever allocated for
// static IPAM — it is a single fixed address, not a dual-stack pool.
func allocateStatic(args *skel.CmdArgs, ipamConf *IPAM) (*IPAMResult, error) {
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
	return &IPAMResult{IPv6Subnet: subnet}, nil
}

// allocatePool allocates a dual-stack, IPv6-only, or IPv4-only pool-based
// endpoint address for the given container, via ipam.DualStackAllocator.
// IPv6Subnet and IPv4Subnet each independently supply a pool CIDR for their
// family; at least one must be set (falling back to localIPAMDefaultPool for
// IPv6 when enableLocalIPAM and both are unset).
func allocatePool(args *skel.CmdArgs, cfg AllocConfig) (*IPAMResult, error) {
	ipv6Pool := cfg.IPv6Subnet
	if ipv6Pool == "" && cfg.IPv4Subnet == "" {
		if !enableLocalIPAM {
			return nil, errors.New("ipv6_subnet or ipv4_subnet is required (or enable local IPAM)")
		}
		ipv6Pool = localIPAMDefaultPool
	}

	alloc, err := ipam.NewDualStackAllocator(ipv6Pool, "", cfg.IPv4Subnet, "", ipv4LockDir)
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

	return &IPAMResult{
		IPv6Subnet:  res.IPv6Subnet,
		IPv6Gateway: res.IPv6Gateway,
		IPv4Address: res.IPv4Address,
		IPv4Gateway: res.IPv4Gateway,
		Routes:      routes,
	}, nil
}

// Deallocate releases the IPAM allocation for the given container. Reads the
// allocated IPv6 subnet and (if present) IPv4 address from the
// BGPAdvertisement CRD annotations galactic-bgp wrote, then deallocates each
// independently and non-fatally: a missing annotation for one family (e.g. a
// pre-existing v6-only pod, or a partial ADD failure that never reached IPv4
// allocation) must not prevent cleanup of the other.
func Deallocate(args *skel.CmdArgs, cfg AllocConfig, k8s client.Client) {
	if cfg.IPAM != nil && cfg.IPAM.Type == TypeStatic {
		// Static allocations don't need deallocation.
		return
	}

	ipv6Subnet, ipv4Addr := getAllocatedSubnetsFromCRD(args.ContainerID, cfg, k8s)
	if ipv6Subnet == "" && ipv4Addr == "" {
		// No allocation found — either allocation was never completed,
		// or the advertisement was already deleted. Nothing to clean up.
		slog.Debug("IPAM: no allocation found to deallocate", "containerID", args.ContainerID)
		return
	}

	if ipv6Subnet != "" {
		ipv6Pool := cfg.IPv6Subnet
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
		if cfg.IPv4Subnet == "" {
			slog.Warn("IPAM: found allocated IPv4 address but no ipv4_subnet in config, skipping deallocation",
				"containerID", args.ContainerID, "address", ipv4Addr)
		} else if pa, err := ipam.NewIPv4PoolAllocator(cfg.IPv4Subnet, "", ipv4LockDir); err != nil {
			slog.Warn("IPAM: failed to build IPv4 pool allocator for deallocation, skipping", "err", err,
				"containerID", args.ContainerID, "address", ipv4Addr)
		} else {
			pa.Deallocate(ipv4Addr)
			slog.Debug("IPAM: deallocated IPv4", "containerID", args.ContainerID, "address", ipv4Addr)
		}
	}
}

// getAllocatedSubnetsFromCRD reads the allocated IPv6 subnet and (if
// present) IPv4 address for the given container from the BGPAdvertisement
// CRD annotations. Either return value is empty when not found.
func getAllocatedSubnetsFromCRD(
	containerID string, cfg AllocConfig, k8s client.Client,
) (ipv6Subnet, ipv4Addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), cniTimeout)
	defer cancel()

	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdnames.BGPAdvertisementName(cfg.VPC, cfg.VPCAttachment),
			Namespace: cfg.Namespace,
		},
	}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(adv), adv); err != nil {
		return "", ""
	}

	return adv.Annotations[crdnames.SubnetKeyIPv6(containerID)], adv.Annotations[crdnames.SubnetKeyIPv4(containerID)]
}
