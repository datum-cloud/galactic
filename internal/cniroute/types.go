// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cniroute implements galactic-route, the termination-route plugin in
// the galactic CNI chain. It is chained after a master plugin and before the BGP
// plugin, and is optional: present only when an attachment has terminations to
// install.
//
// It installs kernel routes into the VRF routing table the master plugin already
// created, then passes the previous result through unchanged, adding no
// interfaces or addresses of its own.
//
// Unlike every other binary in the chain it has no Kubernetes dependency at all:
// it neither reads nor writes any CRD and never needs a namespace.
package cniroute

import (
	"github.com/containernetworking/cni/pkg/types"

	"go.datum.net/galactic/internal/hostconf"
)

// Termination represents a network termination point with a destination
// CIDR and next-hop gateway address.
type Termination struct {
	Network string `json:"network"`
	Via     string `json:"via,omitempty"`
}

// PluginConf is the CNI plugin configuration passed on stdin, the same document
// the master plugin received, since the runtime passes each chain entry its own
// stanza plus the previous result. This plugin reads only the identifiers and
// terminations out of it; the rest belongs to other plugins in the chain.
type PluginConf struct {
	types.PluginConf
	VPC           string        `json:"vpc"`
	VPCAttachment string        `json:"vpcattachment"`
	Terminations  []Termination `json:"terminations,omitempty"`
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf
