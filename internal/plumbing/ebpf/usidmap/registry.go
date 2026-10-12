// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// Registry bundles the read/write API for all four of the uSID datapath's
// control-plane maps against one loaded object set. A convenience constructor
// for callers that would otherwise wrap each map individually.
type Registry struct {
	VRF      *VRFTable
	Locator  *LocatorTable
	Function *FunctionTable

	// VPCAttribution is vpc_attribution_table's read/write API -- a
	// counter-schema-independent companion to VRF, keyed identically. See
	// VPCAttributionTable's doc comment.
	VPCAttribution *VPCAttributionTable

	// Traffic is vrf_traffic_counters' read/write API, nil when the map is
	// not pinned. VRF already keeps its rows in step with vrf_table's.
	Traffic *VRFTrafficTable
}

// NewRegistryFromObjects builds a Registry backed by objs's kernel-loaded
// maps.
func NewRegistryFromObjects(objs *prog.UsidObjects) *Registry {
	traffic := NewVRFTrafficTable(KernelCounterTable{Map: objs.VrfTrafficCounters})
	return &Registry{
		VRF:            NewVRFTable(KernelTable{Map: objs.VrfTable}).WithTraffic(traffic),
		Locator:        NewLocatorTable(KernelTable{Map: objs.LocatorTable}),
		Function:       NewFunctionTable(KernelTable{Map: objs.FunctionTable}),
		VPCAttribution: NewVPCAttributionTable(KernelTable{Map: objs.VpcAttributionTable}),
		Traffic:        traffic,
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

// OpenPinnedRegistry opens the four control-plane maps, and vrf_traffic_counters
// when it is pinned, from their pinned paths
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
	vpcAttributionMap, err := open(prog.UsidMapVpcAttributionTable)
	if err != nil {
		vrfMap.Close()      //nolint:errcheck // best-effort close on partial-open failure
		locatorMap.Close()  //nolint:errcheck // best-effort close on partial-open failure
		functionMap.Close() //nolint:errcheck // best-effort close on partial-open failure
		return nil, nil, err
	}

	closer := pinnedMaps{vrfMap, locatorMap, functionMap, vpcAttributionMap}
	registry := &Registry{
		VRF:            NewVRFTable(KernelTable{Map: vrfMap}),
		Locator:        NewLocatorTable(KernelTable{Map: locatorMap}),
		Function:       NewFunctionTable(KernelTable{Map: functionMap}),
		VPCAttribution: NewVPCAttributionTable(KernelTable{Map: vpcAttributionMap}),
	}

	// vrf_traffic_counters is optional: a datapath loaded by an older
	// galactic-cni has not pinned it, and nothing that forwards depends on it,
	// so no failure to open it fails the caller.
	trafficMap, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapVrfTrafficCounters), nil)
	switch {
	case err == nil:
		closer = append(closer, trafficMap)
		registry.Traffic = NewVRFTrafficTable(KernelCounterTable{Map: trafficMap})
		registry.VRF.WithTraffic(registry.Traffic)
	case !errors.Is(err, os.ErrNotExist):
		slog.Warn("usidmap: could not open the pinned per-VRF traffic counters; continuing without them",
			"map", prog.UsidMapVrfTrafficCounters, "err", err)
	}
	return registry, closer, nil
}
