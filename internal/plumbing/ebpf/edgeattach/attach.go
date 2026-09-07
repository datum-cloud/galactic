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

// Load runs the kernel preflight check and, only if it passes, loads the edge
// program with every map pinned under pinDir. A map already pinned there by a
// previous process is reused as-is.
func Load(pinDir string) (*edgeprog.EdgedsrObjects, error) {
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

	spec, err := edgeprog.LoadEdgedsr()
	if err != nil {
		return nil, fmt.Errorf("edgeattach: load compiled edgedsr collection spec: %w", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	var loaded edgeprog.EdgedsrObjects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	loadErr := spec.LoadAndAssign(&loaded, opts)
	if loadErr != nil && errors.Is(loadErr, ebpf.ErrMapIncompatible) {
		// Every map here is control-plane-owned and reconstructable: the VIP
		// table is repopulated from live CRDs, the statistics map is a
		// pure cache the datapath refills from traffic, and the
		// encapsulation config is a single entry rewritten at process
		// startup. A stale pin from an incompatible layout is safe to
		// recreate rather than fatal.
		slog.Warn("edgeattach: pinned eBPF map incompatible with the newly compiled map spec, recreating "+
			"(control-plane state will repopulate on the next NetworkRule reconcile)", "pinDir", pinDir, "err", loadErr)
		if unpinErr := unpinIncompatibleMaps(spec, pinDir); unpinErr != nil {
			return nil, fmt.Errorf("edgeattach: recreate incompatible pinned maps: %w", unpinErr)
		}
		loadErr = spec.LoadAndAssign(&loaded, opts)
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

// unpinIncompatibleMaps mirrors internal/plumbing/ebpf/attach's identical
// helper -- see that function's doc comment.
func unpinIncompatibleMaps(spec *ebpf.CollectionSpec, pinDir string) error {
	var errs []error
	for name := range spec.Maps {
		path := filepath.Join(pinDir, name)
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			errs = append(errs, fmt.Errorf("load pinned map %q for recreation: %w", name, err))
			continue
		}
		if err := m.Unpin(); err != nil {
			errs = append(errs, fmt.Errorf("unpin stale map %q: %w", name, err))
		}
		_ = m.Close()
	}
	return errors.Join(errs...)
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
	slaves := bond.SlaveNames(iface, links)
	if len(slaves) == 0 {
		return nil, fmt.Errorf(
			"edgeattach: bonding master %q has no slave interfaces to attach the XDP program to", ifaceName)
	}
	return slaves, nil
}

// Attach attaches program to the XDP hook of every interface in ifaceNames, in
// native driver mode, returning the resulting link for each in the same order
// for the caller to hold open and close on shutdown. Callers resolve ifaceNames
// through ResolveTargets first, so this is usually a single interface and never
// a bond master.
//
// If attaching one interface fails partway through, every link already attached
// in this call is closed before returning, so a caller that gets an error holds
// no partial attachment to clean up.
func Attach(program *ebpf.Program, ifaceNames []string) ([]link.Link, error) {
	if program == nil {
		return nil, errors.New("edgeattach: program is nil")
	}
	if len(ifaceNames) == 0 {
		return nil, errors.New("edgeattach: no interfaces to attach to")
	}

	links := make([]link.Link, 0, len(ifaceNames))
	for _, ifaceName := range ifaceNames {
		xdpLink, err := attachOne(program, ifaceName)
		if err != nil {
			for _, already := range links {
				_ = already.Close()
			}
			return nil, err
		}
		links = append(links, xdpLink)
	}
	return links, nil
}

// attachOne attaches program to ifaceName's XDP hook in native driver mode, the
// single-interface mechanism Attach applies across its list.
func attachOne(program *ebpf.Program, ifaceName string) (link.Link, error) {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("edgeattach: find link %q: %w", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"edgeattach: attach XDP program to %q in native/driver mode: %w "+
				"(this program requires native XDP support -- generic/SKB mode is not attempted, "+
				"see this package's doc comment)",
			ifaceName, err,
		)
	}
	return xdpLink, nil
}
