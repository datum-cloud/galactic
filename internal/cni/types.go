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
type IPAM struct {
	Type      string    `json:"type"`                 // "pool" (default) or "static"
	Pool      string    `json:"pool,omitempty"`       // IPv6 CIDR pool, e.g. "fd00:10:ff01::/48"
	Gateway   string    `json:"gateway,omitempty"`    // IPv6 gateway address
	SubnetLen int       `json:"subnet_len,omitempty"` // prefix length per allocation (default 80)
	StaticIP  string    `json:"static_ip,omitempty"`  // used when type="static"
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
type PluginConf struct {
	types.PluginConf
	VPC           string        `json:"vpc"`
	VPCAttachment string        `json:"vpcattachment"`
	MTU           int           `json:"mtu,omitempty"`
	InterfaceType string        `json:"interface_type,omitempty"` // interfaceTypeVeth or interfaceTypeTap
	Terminations  []Termination `json:"terminations,omitempty"`
	IPAM          *IPAM         `json:"ipam"`
	Namespace     string        `json:"namespace,omitempty"`
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf struct {
	NodeName   string `json:"node_name"`
	Kubeconfig string `json:"kubeconfig"`
	Namespace  string `json:"namespace"`
	LogFile    string `json:"log_file"`
}

// ipamResult holds the IPAM allocation details for building the CNI result.
type ipamResult struct {
	subnet  *net.IPNet
	gateway net.IP
	routes  []*net.IPNet
}

// HostDevicePluginConf is the configuration for the host-device CNI plugin
// delegation used to move the guest veth endpoint into the container netns.
type HostDevicePluginConf struct {
	types.PluginConf
	Device string `json:"device"`
}
