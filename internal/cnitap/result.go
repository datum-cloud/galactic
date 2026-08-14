// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"net"

	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/cnimaster"
)

// buildTapResult constructs the CNI result for tap mode: a single host
// interface with optional IPAM data. The guest VM manages its own
// interface; the IP here describes the allocated subnet, which
// galactic-bgp (chained next by the runtime) reads back out of this same
// result to know what to advertise — see internal/cnibgp's doc comment.
// The IPv4 address is reported with a /25 mask, matching the mask
// hostgw.ConfigureHostGateway installs on the host side of the tap.
func buildTapResult(
	pluginConf *PluginConf,
	ipRes *cniipam.IPAMResult,
	hostName, hostMac string,
	hostMTU int,
) *type100.Result {
	result := &type100.Result{
		CNIVersion: pluginConf.CNIVersion,
		Interfaces: []*type100.Interface{
			{
				Name:    hostName,
				Mac:     hostMac,
				Mtu:     hostMTU,
				Sandbox: "",
			},
		},
	}
	cnimaster.AppendIPConfigs(result, ipRes, 0, net.CIDRMask(25, 32)) // index into Interfaces (host tap)
	return result
}
