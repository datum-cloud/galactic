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

	"go.datum.net/galactic/internal/plumbing/ebpf/edgepreflight"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// PinDir is the default bpffs directory every edgeprog map is pinned
// under -- deliberately distinct from internal/plumbing/ebpf/attach.PinDir
// and internal/plumbing/ebpf/gwattach's own PinDir, so every datapath in
// this codebase is fully independent under bpffs even where map names
// don't actually collide.
const PinDir = "/sys/fs/bpf/galactic-edge"

// preflightCheckFn is a package-level override point so tests can force
// the preflight failure path without touching the real kernel -- same
// pattern as internal/plumbing/ebpf/attach's identical var.
var preflightCheckFn = edgepreflight.Check

// Load runs the kernel preflight check and, only if it passes, loads
// edgeprog's compiled object with every map pinned under pinDir. A map
// already pinned there from a previous process is reused as-is; see
// internal/plumbing/ebpf/attach.Load's identical doc comment for the full
// rationale (schema-mismatch recreation, pin-by-name semantics) -- not
// repeated here, since it applies unchanged.
func Load(pinDir string) (*edgeprog.EdgenatObjects, error) {
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

	spec, err := edgeprog.LoadEdgenat()
	if err != nil {
		return nil, fmt.Errorf("edgeattach: load compiled edgenat collection spec: %w", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	var loaded edgeprog.EdgenatObjects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	loadErr := spec.LoadAndAssign(&loaded, opts)
	if loadErr != nil && errors.Is(loadErr, ebpf.ErrMapIncompatible) {
		// Every map here is control-plane-owned and reconstructable
		// (edgemap.RuleTable.Register repopulates rule_table from live
		// NetworkRule CRDs; rule_stats_table and conn_table are both
		// pure caches the datapath itself repopulates from live traffic
		// -- see edgenat.c's struct rule_stats_value doc comment for why
		// rule_stats_table exists separately from rule_table;
		// gw_config_table is a single entry the caller rewrites on every
		// Engine reconcile) -- a stale pin from an older, incompatible
		// map layout is safe to recreate rather than fatal.
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
			return nil, fmt.Errorf("edgeattach: verifier rejected edge_nat program:\n%w", ve)
		}
		return nil, fmt.Errorf("edgeattach: load and pin edgenat objects: %w", loadErr)
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

// Attach attaches program (edgeprog.EdgenatObjects.EdgeNat) to ifaceName's
// XDP hook in native (driver) mode, returning the resulting link.Link for
// the caller to hold open and Close on shutdown -- see doc.go for why
// native mode is required, not merely preferred, and why no pinning or
// Watch-style re-attachment is needed here.
func Attach(program *ebpf.Program, ifaceName string) (link.Link, error) {
	if program == nil {
		return nil, errors.New("edgeattach: program is nil")
	}

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
