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

// buildTapResult constructs the CNI result for tap mode: one host interface with
// optional address data. The guest VM manages its own interface, and the address
// here describes the allocated subnet, which the BGP plugin chained next reads
// back out of this result to know what to advertise. The IPv4 address is
// reported with the same mask the host side of the tap carries.
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
