// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/hostconf"
)

// PluginConf is the CNI plugin configuration passed via stdin on each
// invocation of galactic-cni, the veth master plugin. It's the same shape
// galactic-tap-cni (internal/cnitap) uses — see internal/cnimaster's own
// doc comment — so both packages alias the one canonical definition rather
// than each declaring their own copy.
type PluginConf = cnimaster.PluginConf

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf

// HostDevicePluginConf is the configuration for the host-device CNI plugin
// delegation used to move the guest veth endpoint into the container netns.
type HostDevicePluginConf struct {
	types.PluginConf
	Device string `json:"device"`
}
