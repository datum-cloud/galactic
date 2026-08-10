// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"

	"go.datum.net/galactic/internal/metadata"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

const cniTimeout = 10 * time.Second

// ebpfPinDir is the bpffs directory this package's own eBPF registration
// (registerEBPFDatapath, bgp.go), rollback (resourceTracker.cleanup,
// resource.go), and CHECK (checkEBPFEntry, ops_check.go) all read/write
// pinned uSID maps under. A package var defaulting to attach.PinDir, rather
// than every call site reading that constant directly, so tests can point
// it at a throwaway pin directory instead of the real production one —
// attach.PinDir being a const otherwise gives production callers no seam
// for that (see resource_test.go's resourceTracker.cleanup tests).
var ebpfPinDir = attach.PinDir

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
