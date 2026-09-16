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

// namesRuntimeInterface reports whether the consumer of this result resolves
// the guest's address by the interface name it asked for. containerd does, so
// an attachment it runs must report that name or the sandbox is refused.
// kraftlet instead reads the host device name back out of the result and hands
// it to the platform daemon, so an attachment it runs must report the real
// device.
//
// DAN is the signal that separates them: the runtimes that adopt the tap
// through a Directly Attachable Network file are exactly the ones behind
// containerd. This is the one place that mapping is made, so a future mode that
// needs a different name changes it here.
func namesRuntimeInterface(data []byte) bool {
	return danRequested(data)
}

// buildTapResult constructs the CNI result for tap mode: one interface with
// optional address data. The guest VM manages its own interface, and the
// address here describes the allocated subnet, which the BGP plugin chained
// next reads back out of this result to know what to advertise. The IPv4
// address is reported with the same mask the host side of the tap carries.
//
// The one entry is named for whichever consumer will read it — see
// namesRuntimeInterface — and the caller picks that name. Its MAC and MTU are
// the host tap's: the device the guest attaches to lives in the host
// namespace, which is why the sandbox field stays empty.
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
