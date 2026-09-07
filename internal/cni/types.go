// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/hostconf"
)

// PluginConf is the CNI plugin configuration passed on stdin. It is the same
// shape the tap master uses, so both packages alias the one canonical definition
// rather than each declaring a copy.
type PluginConf = cnimaster.PluginConf

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf

// HostDevicePluginConf is the configuration for the host-device CNI plugin
// delegation used to move the guest veth endpoint into the container netns.
type HostDevicePluginConf struct {
	types.PluginConf
	Device string `json:"device"`
}
