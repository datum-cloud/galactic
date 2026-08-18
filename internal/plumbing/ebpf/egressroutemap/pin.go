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

// OpenPinnedEgressRouteTable opens egress_route_table from its pinned path
// under pinDir (internal/plumbing/ebpf/attach.Load pins every usid_ingress
// map at <pinDir>/<map name> -- see usidmap.OpenPinnedRegistry's identical
// convention) and returns an *EgressRouteTable wrapping it.
//
// The returned io.Closer should be closed once at process shutdown for a
// long-lived caller (galactic-router), or immediately after use for a
// short-lived one (galactic-cni's own per-CNI-ADD/DEL process) --
// mirroring vipxlatmap.OpenPinnedVipXlatTable's identical note; closing
// only releases this process's own file descriptor onto the kernel-side
// map object, never the map's pinned lifetime itself.
func OpenPinnedEgressRouteTable(pinDir string) (*EgressRouteTable, io.Closer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapEgressRouteTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("egressroutemap: open pinned map %q under %q: %w",
			prog.UsidMapEgressRouteTable, pinDir, err)
	}
	return NewEgressRouteTable(usidmap.KernelTable{Map: m}), m, nil
}

// OpenPinnedNodeSourceAddress opens node_src_addr_table from its pinned
// path under pinDir and returns a *NodeSourceAddress wrapping it. See
// OpenPinnedEgressRouteTable's own comment for the pinning convention and
// close-lifetime contract.
func OpenPinnedNodeSourceAddress(pinDir string) (*NodeSourceAddress, io.Closer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapNodeSrcAddrTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("egressroutemap: open pinned map %q under %q: %w",
			prog.UsidMapNodeSrcAddrTable, pinDir, err)
	}
	return &NodeSourceAddress{table: usidmap.KernelTable{Map: m}}, m, nil
}
