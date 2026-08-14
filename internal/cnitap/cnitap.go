// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"

	"go.datum.net/galactic/internal/metadata"
)

// RunPlugin starts the CNI plugin, handling ADD, DEL, CHECK, and STATUS operations.
func RunPlugin() {
	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add:    cmdAdd,
			Check:  cmdCheck,
			Del:    cmdDel,
			Status: cmdStatus,
		},
		version.All,
		"CNI galactic-tap plugin "+metadata.Version,
	)
}
