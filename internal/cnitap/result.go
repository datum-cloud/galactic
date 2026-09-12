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

// buildTapResult constructs the CNI result for tap mode: one interface with
// optional address data. The guest VM manages its own interface, and the
// address here describes the allocated subnet, which the BGP plugin chained
// next reads back out of this result to know what to advertise. The IPv4
// address is reported with the same mask the host side of the tap carries.
//
// The interface is reported under the name the runtime requested, not the host
// tap device name, because a container runtime looks the sandbox's default
// interface up by that name and refuses the sandbox when it carries no
// address. Its MAC and MTU are the host tap's: the device the guest attaches to
// lives in the host namespace, which is why the sandbox field stays empty.
func buildTapResult(
	pluginConf *PluginConf,
	ipRes *cniipam.IPAMResult,
	ifName, hostMac string,
	hostMTU int,
) *type100.Result {
	result := &type100.Result{
		CNIVersion: pluginConf.CNIVersion,
		Interfaces: []*type100.Interface{
			{
				Name:    ifName,
				Mac:     hostMac,
				Mtu:     hostMTU,
				Sandbox: "",
			},
		},
	}
	cnimaster.AppendIPConfigs(result, ipRes, 0, net.CIDRMask(25, 32)) // index into Interfaces (the tap)
	return result
}
