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
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf
