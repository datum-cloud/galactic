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

// buildTapResult constructs the CNI result for tap mode: two entries for the
// same host-namespace tap, plus optional address data on the first. The guest
// VM manages its own interface, and the address here describes the allocated
// subnet, which the BGP plugin chained next reads back out of this result to
// know what to advertise. The IPv4 address is reported with the same mask the
// host side of the tap carries.
//
// The first entry is named for the requesting runtime, since a container
// runtime looks its sandbox's default interface up by that name and refuses
// the sandbox when it carries no address. The second names the actual host
// tap device, which kraftlet reads from the result's last interface. Both
// share the host tap's MAC and MTU, and both leave Sandbox empty: the device
// the guest attaches to lives in the host namespace.
func buildTapResult(
	pluginConf *PluginConf,
	ipRes *cniipam.IPAMResult,
	ifName, hostName, hostMac string,
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
			{
				Name:    hostName,
				Mac:     hostMac,
				Mtu:     hostMTU,
				Sandbox: "",
			},
		},
	}
	cnimaster.AppendIPConfigs(result, ipRes, 0, net.CIDRMask(25, 32)) // index into Interfaces (the runtime-named entry)
	return result
}
