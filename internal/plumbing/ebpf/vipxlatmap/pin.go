// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vipxlatmap

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// OpenPinnedVipXlatTable opens vip_xlat_table from its pinned path under pinDir
// and returns a table wrapping it. The datapath's maps are each pinned at
// <pinDir>/<map name>, the same convention the uSID registry relies on.
//
// The router loads and attaches no eBPF program of its own, that happening once
// elsewhere on the CNI side, so this function's only job is to open a second
// handle onto a map another running process on this node pinned.
//
// Unlike the short-lived plugin binary the uSID registry serves, the router is a
// long-lived daemon: the returned closer should be closed once at process
// shutdown rather than immediately after use. Either way it does not affect the
// map's pinned lifetime, closing only this process's own descriptor.
func OpenPinnedVipXlatTable(pinDir string) (*VipXlatTable, io.Closer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapVipXlatTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("vipxlatmap: open pinned map %q under %q: %w", prog.UsidMapVipXlatTable, pinDir, err)
	}
	return NewVipXlatTable(usidmap.KernelTable{Map: m}), m, nil
}
