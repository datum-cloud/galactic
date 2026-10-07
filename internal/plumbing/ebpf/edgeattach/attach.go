// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeattach

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/bond"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgepreflight"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/mappin"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpattach"
)

// linkByNameFn and linkListFn are override points, as elsewhere in this
// codebase, so ResolveTargets' tests can substitute a fake netlink view without
// touching the host network stack.
var (
	linkByNameFn = netlink.LinkByName
	linkListFn   = netlink.LinkList
)

// PinDir is the default bpffs directory every edge program map is pinned under,
// deliberately distinct from the other datapaths' directories so each is fully
// independent under bpffs even where map names do not collide.
const PinDir = "/sys/fs/bpf/galactic-edge"

// preflightCheckFn is an override point so tests can force the preflight
// failure path without touching the real kernel.
var preflightCheckFn = edgepreflight.Check

// dispatchMapNames are the maps edgedsr.c shares with the node's XDP
// dispatcher (xdpdispatch's dispatch.h). They belong to the dispatcher, never
// to this package: they are not pinned under pinDir, never recreated here, and
// in dispatch mode are replaced with the dispatcher's own pinned maps.
var dispatchMapNames = map[string]bool{
	edgeprog.EdgedsrMapDispatchProgs: true,
	edgeprog.EdgedsrMapIfaceRoles:    true,
	edgeprog.EdgedsrMapSlotLease:     true,
}

// Load runs the kernel preflight check and, only if it passes, loads the edge
// program with every map of its own pinned under pinDir. A map already pinned
// there by a previous process is reused as-is.
//
// dispatchMaps is the node's XDP dispatcher's maps (xdpdispatch.Dispatcher.Maps)
// when the programs run from the dispatcher's slots, and nil when they are
// attached directly. Nil leaves the programs their own empty, unpinned copies,
// so every packet they do not claim passes to the kernel.
func Load(pinDir string, dispatchMaps map[string]*ebpf.Map) (*edgeprog.EdgedsrObjects, error) {
	if err := preflightCheckFn(); err != nil {
		return nil, fmt.Errorf(
			"edgeattach: kernel preflight check failed, refusing to load the edge gateway datapath: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("edgeattach: remove memlock rlimit: %w", err)
	}
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("edgeattach: create bpf map pin directory %q: %w", pinDir, err)
	}

	// Gateways before the shared dispatcher pinned a one-slot program array
	// here, xdp_chain, that the egress shard filled. Nothing reads it now, so
	// it only keeps a retired shard program loaded, and a shard not yet
	// upgraded would install itself into a map no datapath runs and look
	// healthy. Remove it.
	legacyChain := filepath.Join(pinDir, "xdp_chain")
	if err := os.Remove(legacyChain); err == nil {
		slog.Info("edgeattach: removed the retired xdp_chain pin; the egress shard now runs from the XDP dispatcher",
			"path", legacyChain)
	} else if !errors.Is(err, os.ErrNotExist) {
		slog.Warn("edgeattach: cannot remove the retired xdp_chain pin", "path", legacyChain, "err", err)
	}

	spec, err := edgeprog.LoadEdgedsr()
	if err != nil {
		return nil, fmt.Errorf("edgeattach: load compiled edgedsr collection spec: %w", err)
	}
	for name, m := range spec.Maps {
		if !dispatchMapNames[name] {
			m.Pinning = ebpf.PinByName
		}
	}

	var loaded edgeprog.EdgedsrObjects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}, MapReplacements: dispatchMaps}
	loadErr := spec.LoadAndAssign(&loaded, opts)
	if loadErr != nil && errors.Is(loadErr, ebpf.ErrMapIncompatible) {
		// Every map here is control-plane-owned and reconstructable: the VIP
		// table is repopulated from live CRDs, the statistics map is a
		// pure cache the datapath refills from traffic, and the
		// encapsulation config is a single entry rewritten at process
		// startup. A stale pin from an incompatible layout is safe to
		// recreate rather than fatal. The dispatcher's maps are not ours and
		// are never touched here.
		unpinned, unpinErr := mappin.UnpinIncompatible(spec, pinDir, func(name string) bool { return dispatchMapNames[name] })
		if unpinErr != nil {
			return nil, fmt.Errorf("edgeattach: recreate incompatible pinned maps: %w", unpinErr)
		}
		if len(unpinned) == 0 {
			return nil, fmt.Errorf("edgeattach: load reported an incompatible map, but every pin under %s matches: %w",
				pinDir, loadErr)
		}
		slog.Warn("edgeattach: pinned eBPF maps incompatible with the newly compiled map spec, recreating them "+
			"(control-plane state will repopulate on the next NetworkRule reconcile)",
			"pinDir", pinDir, "maps", unpinned, "err", loadErr)
		if loadErr = spec.LoadAndAssign(&loaded, opts); loadErr != nil {
			loadErr = fmt.Errorf("after recreating %v: %w", unpinned, loadErr)
		}
	}
	if loadErr != nil {
		var ve *ebpf.VerifierError
		if errors.As(loadErr, &ve) {
			return nil, fmt.Errorf("edgeattach: verifier rejected edge_lb program:\n%w", ve)
		}
		return nil, fmt.Errorf("edgeattach: load and pin edgedsr objects: %w", loadErr)
	}
	return &loaded, nil
}

// ResolveTargets resolves ifaceName to the interface names Attach should
// actually attach the XDP program to.
//
// An interface that is not a bonding master resolves to itself, the common
// case. A bonding master resolves to its slaves instead, with the master
// excluded: unlike the TC-BPF path, which attaches to both because the master
// still carries the filter attachment point, native XDP against a bonding
// master is not reliable and fails outright on real hardware. Some kernels'
// bonding driver does forward the attach to every slave, but that still
// requires each slave's driver to support native XDP, which is not a given, so
// this attaches only to real slaves whose support can be reasoned about
// directly.
//
// A bonding master with no slaves is an error: attaching nothing, or attaching
// to the master and risking the failure this exists to avoid, would leave the
// gateway datapath running with no ingress attachment at all.
func ResolveTargets(ifaceName string) ([]string, error) {
	iface, err := linkByNameFn(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("edgeattach: find link %q: %w", ifaceName, err)
	}
	if !bond.IsMaster(iface) {
		return []string{ifaceName}, nil
	}

	links, err := linkListFn()
	if err != nil {
		return nil, fmt.Errorf("edgeattach: enumerate slaves of bonding master %q: %w", ifaceName, err)
	}
	targets, err := bond.XDPTargets(iface, links)
	if err != nil {
		return nil, fmt.Errorf("edgeattach: %w", err)
	}
	return targets, nil
}

// Attach attaches program to the XDP hook of every interface in ifaceNames, in
// native driver mode, returning the resulting link for each in the same order
// for the caller to hold open and close on shutdown. Callers resolve ifaceNames
// through ResolveTargets first, so this is usually a single interface and never
// a bond master.
//
// The attach itself is xdpattach.Attach, which checks every interface for
// native XDP support before touching any of them and waits each bond slave back
// into its aggregate before attaching the next, so a bonded uplink never loses
// every member at once. A failure partway through closes every link already
// attached in this call.
func Attach(program *ebpf.Program, ifaceNames []string) ([]link.Link, error) {
	if program == nil {
		return nil, errors.New("edgeattach: program is nil")
	}
	if len(ifaceNames) == 0 {
		return nil, errors.New("edgeattach: no interfaces to attach to")
	}
	links, err := xdpattach.Attach(program, ifaceNames)
	if err != nil {
		return nil, fmt.Errorf("edgeattach: %w", err)
	}
	return links, nil
}
