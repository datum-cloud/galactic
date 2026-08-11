// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"

	"go.datum.net/galactic/internal/metadata"
)

// pluginName is used in the "about" string skel prints when invoked with no
// CNI_COMMAND, and mirrors the "type" field this plugin is expected to be
// registered under in the conflist chain.
const pluginName = "vmtap-cni"

// RunPlugin starts the CNI plugin, handling ADD, DEL, and CHECK operations.
// STATUS is intentionally omitted (optional per the CNI spec): unlike
// galactic-veth, vmtap-cni has no Kubernetes API dependency or node-level
// bootstrap state to probe readiness against.
func RunPlugin() {
	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add:   cmdAdd,
			Check: cmdCheck,
			Del:   cmdDel,
		},
		version.All,
		"CNI "+pluginName+" plugin "+metadata.Version,
	)
}
