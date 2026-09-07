// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// OpenPinnedEgressRouteTable opens egress_route_table from its pinned path under
// pinDir and returns a table wrapping it. The datapath's maps are each pinned at
// <pinDir>/<map name>.
//
// The returned closer should be closed once at process shutdown for a long-lived
// caller, or immediately after use for a short-lived one. Either way it releases
// only this process's own descriptor, never the map's pinned lifetime.
func OpenPinnedEgressRouteTable(pinDir string) (*EgressRouteTable, io.Closer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapEgressRouteTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("egressroutemap: open pinned map %q under %q: %w",
			prog.UsidMapEgressRouteTable, pinDir, err)
	}
	return NewEgressRouteTable(usidmap.KernelTable{Map: m}), m, nil
}

// OpenPinnedNodeSourceAddress opens node_src_addr_table from its pinned path
// under pinDir and returns a wrapper. See OpenPinnedEgressRouteTable for the
// pinning convention and close contract.
func OpenPinnedNodeSourceAddress(pinDir string) (*NodeSourceAddress, io.Closer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapNodeSrcAddrTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("egressroutemap: open pinned map %q under %q: %w",
			prog.UsidMapNodeSrcAddrTable, pinDir, err)
	}
	return &NodeSourceAddress{table: usidmap.KernelTable{Map: m}}, m, nil
}

// OpenPinnedPublicUplink opens public_uplink_table from its pinned path under
// pinDir and returns a wrapper. See OpenPinnedEgressRouteTable for the pinning
// convention and close contract.
func OpenPinnedPublicUplink(pinDir string) (*PublicUplink, io.Closer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapPublicUplinkTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("egressroutemap: open pinned map %q under %q: %w",
			prog.UsidMapPublicUplinkTable, pinDir, err)
	}
	return &PublicUplink{table: usidmap.KernelTable{Map: m}}, m, nil
}
