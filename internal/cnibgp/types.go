// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/hostconf"
)

// PluginConf is the CNI plugin configuration passed on stdin, the same document
// the master plugin received, since the runtime passes each chain entry its own
// stanza plus the previous result. This plugin reads only the identifiers and
// namespace out of it; the rest belongs to other plugins in the chain.
type PluginConf struct {
	types.PluginConf
	VPC           string `json:"vpc"`
	VPCAttachment string `json:"vpcattachment"`
	Namespace     string `json:"namespace,omitempty"`

	// Egress is this network's internet egress declaration, written into the
	// stanza by whoever renders it from the network's declared intent. Absent,
	// or anything but Enabled, installs no egress route for the VRF and
	// withdraws one that is there.
	Egress *Egress `json:"egress,omitempty"`
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf

// Egress is the per-network internet egress declaration. It names no shard:
// the node routes toward the shard its own configuration names, so the
// declaration decides only whether this VRF gets that route.
//
// It is per network because egress is per network. The node-wide shard list
// on its own gives every network on the node a default route out, including
// every network that declared no egress, so the list cannot express a network
// that opted out. The declaration can.
type Egress struct {
	Internet *InternetEgress `json:"internet,omitempty"`
}

// InternetEgressEnabled is the one mode a node acts on.
const InternetEgressEnabled = "Enabled"

// InternetEgress is whether this network reaches the internet.
type InternetEgress struct {
	Mode string `json:"mode"`
}

// Enabled reports whether a declaration asks for an egress route. A nil
// declaration, or any mode but Enabled, does not.
func (e *Egress) Enabled() bool {
	return e != nil && e.Internet != nil && e.Internet.Mode == InternetEgressEnabled
}
