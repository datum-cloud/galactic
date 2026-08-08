// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/cni/hostconf"
	"go.datum.net/galactic/internal/cniipam"
)

// PluginConf is the CNI plugin configuration passed via stdin on each
// invocation of galactic-cni, the veth master plugin.
//
// IPAM addressing fields (ipv6_subnet, ipv4_subnet, address_families,
// static_ip) live entirely inside the "ipam" block now — see
// go.datum.net/galactic/internal/cniipam's doc comment for the explicit
// delegation contract: this struct only decides *whether* to delegate
// (IPAM != nil), never anything about how allocation itself works.
// Termination routes are galactic-route's own concern now (see
// internal/cniroute) — this plugin's own JSON stanza carries no
// "terminations" field of its own to read.
type PluginConf struct {
	types.PluginConf
	VPC           string        `json:"vpc"`
	VPCAttachment string        `json:"vpcattachment"`
	MTU           int           `json:"mtu,omitempty"`
	IPAM          *cniipam.IPAM `json:"ipam"`
	Namespace     string        `json:"namespace,omitempty"`
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf

// HostDevicePluginConf is the configuration for the host-device CNI plugin
// delegation used to move the guest veth endpoint into the container netns.
type HostDevicePluginConf struct {
	types.PluginConf
	Device string `json:"device"`
}
