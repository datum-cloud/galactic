// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"errors"
	"fmt"
	"io"
	"os"
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
	return NewNodeSourceAddress(usidmap.KernelTable{Map: m}), m, nil
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
	return NewPublicUplink(usidmap.KernelTable{Map: m}), m, nil
}

// OpenPinnedShardGroupTable opens egress_shard_groups from its pinned path
// under pinDir and returns a table over it. See OpenPinnedEgressRouteTable for
// the pinning convention and close contract.
//
// A datapath older than the shard group map has no such pin, and the error
// then matches os.ErrNotExist.
func OpenPinnedShardGroupTable(pinDir string) (*ShardGroupTable, io.Closer, error) {
	outer, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapEgressShardGroups), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("egressroutemap: open pinned map %q under %q: %w",
			prog.UsidMapEgressShardGroups, pinDir, err)
	}
	table := NewShardGroupTable(NewKernelGroupStore(outer))
	// A datapath older than the local views has no egress_shard_local_groups:
	// the table then publishes the base view alone, which is all that
	// datapath reads.
	local, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapEgressShardLocalGroups), nil)
	switch {
	case err == nil:
		table.WithLocalView(NewKernelGroupStore(local))
		return table, closers{outer, local}, nil
	case errors.Is(err, os.ErrNotExist):
		return table, outer, nil
	default:
		_ = outer.Close()
		return nil, nil, fmt.Errorf("egressroutemap: open pinned map %q under %q: %w",
			prog.UsidMapEgressShardLocalGroups, pinDir, err)
	}
}

// closers closes each of its members, joining their errors.
type closers []io.Closer

func (c closers) Close() error {
	errs := make([]error, 0, len(c))
	for _, m := range c {
		errs = append(errs, m.Close())
	}
	return errors.Join(errs...)
}
