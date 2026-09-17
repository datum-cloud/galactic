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

	// Egress carries this network's internet egress instruction. Absent means
	// the network declared no egress, which installs no egress route -- see
	// Egress's own doc comment.
	Egress *Egress `json:"egress,omitempty"`
}

// Egress is the per-network internet egress instruction, written into this
// plugin's conflist stanza by whoever generates it from the network's declared
// intent.
//
// It is per network because egress is per network. A node-wide shard list
// gives every network on the node a default route out, including every network
// that declared no egress at all, so the node-wide form cannot express a
// network that opted out -- it can only express a node that has no egress for
// anybody.
//
// Absent, or present with an empty ShardSIDs, installs no egress route. The
// two differ only in what they fall back to: an absent key defers to the
// deprecated node-wide environment variable, for a node part-way through a
// rollout, while an empty list is an explicit statement that this network has
// no egress and overrides that variable.
type Egress struct {
	// ShardSIDs is the ordered list of candidate egress shard SIDs this
	// network's traffic may leave through. The first entry whose SID resolves
	// to a route wins; a node that is itself one of these shards cannot
	// resolve a route to its own self-originated SID, which is why an
	// unresolvable entry is skipped rather than fatal.
	ShardSIDs []string `json:"shardSIDs,omitempty"`
}

// HostConf holds node-local settings read from /etc/cni/net.d/10-galactic.conflist.
type HostConf = hostconf.HostConf
