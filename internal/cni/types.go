// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"net"

	"github.com/containernetworking/cni/pkg/types"
)

// Termination represents a network termination point with a destination
// CIDR and next-hop gateway address.
type Termination struct {
	Network string `json:"network"`
	Via     string `json:"via,omitempty"`
}

// IPAM holds IP address management configuration passed in the CNI config.
// Pool CIDR fields (formerly Pool/Gateway/SubnetLen) have been retired in
// favor of PluginConf.IPv6Subnet/IPv4Subnet — see allocateIPAM.
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

// PluginConf is the CNI plugin configuration passed via stdin on each invocation.
//
// IPv6Subnet, IPv4Subnet, and AddressFamilies feed the dual-stack IPAM
// allocators (internal/cni/ipam, IPv4PoolAllocator/DualStackAllocator); as of
// this change allocateIPAM does not yet consume them, and format/requiredness
// validation in parseConf lands in a later phase.
type PluginConf struct {
	types.PluginConf
	VPC string `json:"vpc"`
	// VPCName is the VPC CR's Kubernetes object name, distinct from the
	// base62 VPC identifier above — see applyVPCAttachment (vpcattachment.go).
	VPCName         string        `json:"vpc_name,omitempty"`
	VPCAttachment   string        `json:"vpcattachment"`
	MTU             int           `json:"mtu,omitempty"`
	InterfaceType   string        `json:"interface_type,omitempty"` // interfaceTypeVeth or interfaceTypeTap
	Terminations    []Termination `json:"terminations,omitempty"`
	IPAM            *IPAM         `json:"ipam"`
	Namespace       string        `json:"namespace,omitempty"`
	IPv6Subnet      string        `json:"ipv6_subnet,omitempty"`      // region IPv6 pool CIDR; endpoints alloc /96
	IPv4Subnet      string        `json:"ipv4_subnet,omitempty"`      // optional site IPv4 pool CIDR; endpoints alloc /32
	AddressFamilies []string      `json:"address_families,omitempty"` // families to allocate; default ["ipv6"]
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf struct {
	NodeName   string `json:"node_name"`
	Kubeconfig string `json:"kubeconfig"`
	Namespace  string `json:"namespace"`
	LogFile    string `json:"log_file"`
	LogLevel   string `json:"log_level,omitempty"`
}

// ipamResult holds the IPAM allocation details for building the CNI result.
// ipv4Address/ipv4Gateway are nil when the attachment is IPv6-only.
type ipamResult struct {
	ipv6Subnet  *net.IPNet
	ipv6Gateway net.IP
	ipv4Address net.IP
	ipv4Gateway net.IP
	routes      []*net.IPNet
}

// HostDevicePluginConf is the configuration for the host-device CNI plugin
// delegation used to move the guest veth endpoint into the container netns.
type HostDevicePluginConf struct {
	types.PluginConf
	Device string `json:"device"`
}
