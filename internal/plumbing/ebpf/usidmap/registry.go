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

// Registry bundles the read/write API for all three of the uSID datapath's
// control-plane maps against one loaded object set. A convenience constructor
// for callers that would otherwise wrap each map individually.
type Registry struct {
	VRF      *VRFTable
	Locator  *LocatorTable
	Function *FunctionTable
}

// NewRegistryFromObjects builds a Registry backed by objs's kernel-loaded
// maps.
func NewRegistryFromObjects(objs *prog.UsidObjects) *Registry {
	return &Registry{
		VRF:      NewVRFTable(KernelTable{Map: objs.VrfTable}),
		Locator:  NewLocatorTable(KernelTable{Map: objs.LocatorTable}),
		Function: NewFunctionTable(KernelTable{Map: objs.FunctionTable}),
	}
}

// pinnedMaps is the closer OpenPinnedRegistry returns. Closing it closes every
// map handle this process opened: opening a pinned map hands back a new
// descriptor onto the same kernel object the control daemon loaded, and closing
// it affects neither the pinned map nor any other process's handle.
type pinnedMaps []*ebpf.Map

func (p pinnedMaps) Close() error {
	for _, m := range p {
		m.Close() //nolint:errcheck // best-effort close of our own fd; nothing actionable on failure
	}
	return nil
}

// OpenPinnedRegistry opens the three control-plane maps from their pinned paths
// under pinDir and returns a Registry wrapping them, for a short-lived process
// that did not itself load the datapath but needs to read and write its maps.
// The returned closer must be closed when the caller is done; the maps stay
// pinned across any process's open and close cycle.
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
