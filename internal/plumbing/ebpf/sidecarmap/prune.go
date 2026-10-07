// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sidecarmap removes the rows the ingress sidecar (internal/
// ingresssidecar) writes into the node's shared, pinned eBPF maps.
//
// The sidecar writes those rows from inside its pod's network namespace and
// deliberately leaves them in place when it exits, so a sidecar restarting in
// the same pod picks its datapath back up without a blackout. A pod that is
// deleted, though, takes its VRFs and veths with it and leaves the rows behind,
// and nothing else ever removes them: the host's sweeps leave the sidecar's
// share of every map alone, since they cannot read the pod's namespace.
//
// Every row the sidecar writes is recognisable from its key alone, because each
// map is split into ranges no host writer reaches:
//
//   - vrf_table rows under uformat.BlockIngressSidecar
//   - ifindex_vrf_table rows at or above ifindexvrfmap.SidecarIfindexBase
//   - egress_route_table rows for routing tables at or above
//     vrf.SidecarTableIDBase
//
// Each range also encodes the VRF's uSID Argument, which is what a caller names
// the rows to keep by.
package sidecarmap

import (
	"errors"
	"fmt"
	"io"
	"net"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// Maps are the three maps the ingress sidecar writes rows into.
type Maps struct {
	VRF         *usidmap.VRFTable
	Ifindex     *ifindexvrfmap.IfindexVRFTable
	EgressRoute *egressroutemap.EgressRouteTable
}

// OpenPinned opens the three maps from their pins under pinDir. The returned
// closer releases this process's handles and must be closed when the caller is
// done; the maps stay pinned.
func OpenPinned(pinDir string) (Maps, io.Closer, error) {
	registry, registryCloser, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return Maps{}, nil, fmt.Errorf("sidecarmap: open pinned vrf_table: %w", err)
	}
	ifindexTable, ifindexCloser, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		_ = registryCloser.Close()
		return Maps{}, nil, fmt.Errorf("sidecarmap: %w", err)
	}
	routeTable, routeCloser, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		_ = registryCloser.Close()
		_ = ifindexCloser.Close()
		return Maps{}, nil, fmt.Errorf("sidecarmap: %w", err)
	}
	m := Maps{VRF: registry.VRF, Ifindex: ifindexTable, EgressRoute: routeTable}
	return m, closers{registryCloser, ifindexCloser, routeCloser}, nil
}

// closers closes every handle OpenPinned opened.
type closers []io.Closer

func (c closers) Close() error {
	errs := make([]error, 0, len(c))
	for _, closer := range c {
		errs = append(errs, closer.Close())
	}
	return errors.Join(errs...)
}

// Result counts the rows Prune removed from each map.
type Result struct {
	VRFRows         int
	IfindexRows     int
	EgressRouteRows int
}

// Total is the number of rows removed across every map.
func (r Result) Total() int {
	return r.VRFRows + r.IfindexRows + r.EgressRouteRows
}

// Prune removes every ingress sidecar row whose uSID Argument is not in keep.
// A nil or empty keep removes all of them.
//
// Host rows are never touched: each map is filtered to the sidecar's own key
// range before anything is deleted. Every map is attempted even if an earlier
// one fails, and the failures are joined.
func Prune(m Maps, keep map[uint16]struct{}) (Result, error) {
	var (
		result Result
		errs   []error
	)
	kept := func(argument uint16) bool {
		_, ok := keep[argument]
		return ok
	}

	if entries, err := m.VRF.List(); err != nil {
		errs = append(errs, err)
	} else {
		for _, e := range entries {
			if e.Block != uformat.BlockIngressSidecar || kept(e.Argument) {
				continue
			}
			if err := m.VRF.Unregister(e.Block, e.Argument); err != nil {
				errs = append(errs, err)
				continue
			}
			result.VRFRows++
		}
	}

	if entries, err := m.Ifindex.List(); err != nil {
		errs = append(errs, err)
	} else {
		for _, e := range entries {
			if e.Ifindex < ifindexvrfmap.SidecarIfindexBase {
				continue
			}
			// The index, not the row's value, says which Argument it is
			// for: the sidecar creates each interface at exactly
			// SidecarIfindex(argument).
			offset := e.Ifindex - ifindexvrfmap.SidecarIfindexBase
			if offset <= uint32(uformat.ArgumentMax) && kept(uint16(offset)) {
				continue
			}
			if err := m.Ifindex.Unregister(e.Ifindex); err != nil {
				errs = append(errs, err)
				continue
			}
			result.IfindexRows++
		}
	}

	if byTable, err := m.EgressRoute.Prefixes(); err != nil {
		errs = append(errs, err)
	} else {
		for tableID, prefixes := range byTable {
			if tableID < vrf.SidecarTableIDBase {
				continue
			}
			offset := tableID - vrf.SidecarTableIDBase
			if offset <= uint32(uformat.ArgumentMax) && kept(uint16(offset)) {
				continue
			}
			for p := range prefixes {
				_, prefix, err := net.ParseCIDR(p)
				if err != nil {
					errs = append(errs, fmt.Errorf("sidecarmap: parse egress_route_table prefix %q: %w", p, err))
					continue
				}
				if err := m.EgressRoute.Unregister(tableID, prefix); err != nil {
					errs = append(errs, err)
					continue
				}
				result.EgressRouteRows++
			}
		}
	}

	return result, errors.Join(errs...)
}
