// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/hostconf"
)

// PluginConf is the CNI plugin configuration passed via stdin on each
// invocation of galactic-bgp — the same document the master plugin itself
// received, since the CNI runtime passes each chain entry its own stanza
// plus prevResult; galactic-bgp only reads vpc/vpcattachment/namespace out
// of it (mtu, terminations, ipam are the master's/galactic-ipam's own
// concerns).
type PluginConf struct {
	types.PluginConf
	VPC           string `json:"vpc"`
	VPCAttachment string `json:"vpcattachment"`
	Namespace     string `json:"namespace,omitempty"`
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf
