// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"

	"go.datum.net/galactic/internal/metadata"
)

const cniTimeout = 10 * time.Second

// RunPlugin starts galactic-bgp, handling the CNI ADD, DEL, CHECK, and
// STATUS operations for the BGP/SRv6/eBPF publish stage of the chain.
func RunPlugin() {
	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add:    cmdAdd,
			Check:  cmdCheck,
			Del:    cmdDel,
			Status: cmdStatus,
		},
		version.All,
		"CNI galactic-bgp plugin "+metadata.Version,
	)
}
