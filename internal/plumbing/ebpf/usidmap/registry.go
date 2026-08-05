// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// Registry bundles the read/write API for all three of the eBPF uSID
// datapath's control-plane maps, wired against a single loaded
// *prog.UsidObjects. It exists purely as a convenience constructor for
// production callers (Milestones 3.1/7.1/7.2/7.3) that otherwise have to
// wrap each of the three maps in its own KernelTable individually.
type Registry struct {
	VRF      *VRFTable
	Locator  *LocatorTable
	Function *FunctionTable
}

// NewRegistryFromObjects builds a Registry backed by objs's real,
// kernel-loaded maps (e.g. the *prog.UsidObjects returned by
// internal/plumbing/ebpf/attach.Load or .Start).
func NewRegistryFromObjects(objs *prog.UsidObjects) *Registry {
	return &Registry{
		VRF:      NewVRFTable(KernelTable{Map: objs.VrfTable}),
		Locator:  NewLocatorTable(KernelTable{Map: objs.LocatorTable}),
		Function: NewFunctionTable(KernelTable{Map: objs.FunctionTable}),
	}
}

// pinnedMaps is the io.Closer OpenPinnedRegistry returns: closing it closes
// every *ebpf.Map handle this process itself opened (design plan §5.4 --
// opening a pinned map hands back a new fd referencing the same
// kernel-side map object the control daemon already loaded; that fd is
// this process's own to close, and doing so does not affect the
// underlying pinned map or any other process's handle to it).
type pinnedMaps []*ebpf.Map

func (p pinnedMaps) Close() error {
	for _, m := range p {
		m.Close() //nolint:errcheck // best-effort close of our own fd; nothing actionable on failure
	}
	return nil
}

// OpenPinnedRegistry opens vrf_table, locator_table, and function_table
// from their pinned paths under pinDir (internal/plumbing/ebpf/attach.Load
// pins each map at <pinDir>/<map name>, e.g. <pinDir>/vrf_table) and
// returns a Registry wrapping them, for a short-lived process -- namely
// the galactic-cni plugin binary's ADD path (Milestones 7.1/7.2) -- that
// did not itself load the datapath but needs to read/write its maps. The
// returned io.Closer must be closed once the caller is done; it does not
// affect the maps' pinned lifetime (design plan §4.4: maps stay pinned
// across any single process's open/close cycle).
func OpenPinnedRegistry(pinDir string) (*Registry, pinnedMaps, error) {
	open := func(name string) (*ebpf.Map, error) {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			return nil, fmt.Errorf("open pinned map %q: %w", name, err)
		}
		return m, nil
	}

	vrfMap, err := open(prog.UsidMapVrfTable)
	if err != nil {
		return nil, nil, err
	}
	locatorMap, err := open(prog.UsidMapLocatorTable)
	if err != nil {
		vrfMap.Close() //nolint:errcheck // best-effort close on partial-open failure
		return nil, nil, err
	}
	functionMap, err := open(prog.UsidMapFunctionTable)
	if err != nil {
		vrfMap.Close()     //nolint:errcheck // best-effort close on partial-open failure
		locatorMap.Close() //nolint:errcheck // best-effort close on partial-open failure
		return nil, nil, err
	}

	closer := pinnedMaps{vrfMap, locatorMap, functionMap}
	return &Registry{
		VRF:      NewVRFTable(KernelTable{Map: vrfMap}),
		Locator:  NewLocatorTable(KernelTable{Map: locatorMap}),
		Function: NewFunctionTable(KernelTable{Map: functionMap}),
	}, closer, nil
}
