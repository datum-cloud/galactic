// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cnitap implements galactic-tap-cni, the tap master plugin for
// VM-based workloads (Kata, Firecracker, kraftlet/Unikraft). It mirrors
// internal/cni (the veth master, galactic-cni) but never delegates to
// host-device (no container netns to move anything into — the VM manages
// its own guest interface) and never configures a guest-side netns.
package cnitap

import (
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/cni/hostconf"
	"go.datum.net/galactic/internal/cniipam"
)

// Termination represents a network termination point with a destination
// CIDR and next-hop gateway address.
type Termination struct {
	Network string `json:"network"`
	Via     string `json:"via,omitempty"`
}

// PluginConf is the CNI plugin configuration passed via stdin on each
// invocation of galactic-tap-cni.
type PluginConf struct {
	types.PluginConf
	VPC             string        `json:"vpc"`
	VPCAttachment   string        `json:"vpcattachment"`
	MTU             int           `json:"mtu,omitempty"`
	Terminations    []Termination `json:"terminations,omitempty"`
	IPAM            *cniipam.IPAM `json:"ipam"`
	Namespace       string        `json:"namespace,omitempty"`
	IPv6Subnet      string        `json:"ipv6_subnet,omitempty"`
	IPv4Subnet      string        `json:"ipv4_subnet,omitempty"`
	AddressFamilies []string      `json:"address_families,omitempty"`
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf

// allocConfig adapts pluginConf's fields into cniipam.AllocConfig.
func allocConfig(pluginConf *PluginConf) cniipam.AllocConfig {
	return cniipam.AllocConfig{
		VPC:             pluginConf.VPC,
		VPCAttachment:   pluginConf.VPCAttachment,
		Namespace:       pluginConf.Namespace,
		IPAM:            pluginConf.IPAM,
		IPv6Subnet:      pluginConf.IPv6Subnet,
		IPv4Subnet:      pluginConf.IPv4Subnet,
		AddressFamilies: pluginConf.AddressFamilies,
	}
}
