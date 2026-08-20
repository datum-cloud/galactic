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

// OpenPinnedVipXlatTable opens vip_xlat_table from its pinned path under
// pinDir (internal/plumbing/ebpf/attach.Load pins every usid_ingress map at
// <pinDir>/<map name>, e.g. <pinDir>/vip_xlat_table -- the same convention
// usidmap.OpenPinnedRegistry already documents and relies on for
// vrf_table/locator_table/function_table) and returns a *VipXlatTable
// wrapping it.
//
// This is new plumbing: nothing in this codebase needed galactic-router to
// reach any of usid.c's maps before the DSR/Maglev tap-VIP substitution --
// galactic-router loads/attaches no eBPF program of its own (that happens
// once, elsewhere, driven by galactic-cni/internal/plumbing/ebpf/attach on
// the CNI side), so this function's only job is to open a *second* handle
// onto maps some other, already-running process on this node pinned --
// exactly usidmap.OpenPinnedRegistry's own established pattern, reused here
// for the one additional map that pattern didn't yet cover.
//
// Unlike usidmap.OpenPinnedRegistry's intended caller (the short-lived
// galactic-cni plugin binary, one process per CNI ADD/DEL), galactic-router
// is a long-lived daemon: the returned io.Closer should be closed once at
// process shutdown, not immediately after use -- it does not affect the
// map's pinned lifetime either way (closing only releases this process's
// own file descriptor onto the kernel-side map object).
func OpenPinnedVipXlatTable(pinDir string) (*VipXlatTable, io.Closer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapVipXlatTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("vipxlatmap: open pinned map %q under %q: %w", prog.UsidMapVipXlatTable, pinDir, err)
	}
	return NewVipXlatTable(usidmap.KernelTable{Map: m}), m, nil
}
