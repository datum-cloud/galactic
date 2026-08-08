// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cniroute implements galactic-route, the termination-route plugin
// in the galactic CNI chain — chained after galactic-cni/galactic-tap-cni
// and before galactic-bgp per conflist order (optional: only present when
// an attachment has terminations to install). It installs kernel routes
// into the VRF routing table the preceding master plugin already created,
// then passes prevResult through unchanged, adding no interfaces or IPs of
// its own.
//
// Unlike every other binary in the chain, galactic-route has no Kubernetes
// dependency at all: it neither reads nor writes any CRD, and never needs
// a namespace.
package cniroute

import (
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/cni/hostconf"
)

// Termination represents a network termination point with a destination
// CIDR and next-hop gateway address.
type Termination struct {
	Network string `json:"network"`
	Via     string `json:"via,omitempty"`
}

// PluginConf is the CNI plugin configuration passed via stdin on each
// invocation of galactic-route — the same document the master plugin
// itself received, since the CNI runtime passes each chain entry its own
// stanza plus prevResult. galactic-route only reads vpc/vpcattachment/
// terminations out of it (mtu, ipam, namespace are the master's/
// galactic-ipam's/galactic-bgp's own concerns).
type PluginConf struct {
	types.PluginConf
	VPC           string        `json:"vpc"`
	VPCAttachment string        `json:"vpcattachment"`
	Terminations  []Termination `json:"terminations,omitempty"`
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf
