// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nat66attach

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

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
)

// PinDir is the default bpffs directory every NAT66 map is pinned under,
// deliberately distinct from every other datapath's, so each is fully
// independent under bpffs even where map names do not collide.
const PinDir = "/sys/fs/bpf/galactic-nat66"

// Load loads the compiled NAT66 object with every map pinned under pinDir. A
// map already pinned there by a previous process is reused as-is. See the
// package doc comment for why, unlike its sibling, there is no kernel preflight
// check here.
func Load(pinDir string) (*nat66prog.Nat66Objects, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("nat66attach: remove memlock rlimit: %w", err)
	}
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("nat66attach: create bpf map pin directory %q: %w", pinDir, err)
	}

	spec, err := nat66prog.LoadNat66()
	if err != nil {
		return nil, fmt.Errorf("nat66attach: load compiled nat66 collection spec: %w", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	var loaded nat66prog.Nat66Objects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	loadErr := spec.LoadAndAssign(&loaded, opts)
	if loadErr != nil && errors.Is(loadErr, ebpf.ErrMapIncompatible) {
		// Every map here is either control-plane-owned and reconstructable,
		// the shard config being rewritten at process startup, or
		// datapath-owned and self-managing, the connection table being an
		// LRU that self-evicts and the drop counters a pure array. A stale
		// pin from an incompatible layout is safe to recreate.
		slog.Warn("nat66attach: pinned eBPF map incompatible with the newly compiled map spec, recreating "+
			"(control-plane state will repopulate at next startup)", "pinDir", pinDir, "err", loadErr)
		if unpinErr := unpinIncompatibleMaps(spec, pinDir); unpinErr != nil {
			return nil, fmt.Errorf("nat66attach: recreate incompatible pinned maps: %w", unpinErr)
		}
		loadErr = spec.LoadAndAssign(&loaded, opts)
	}
	if loadErr != nil {
		var ve *ebpf.VerifierError
		if errors.As(loadErr, &ve) {
			return nil, fmt.Errorf("nat66attach: verifier rejected nat66_ingress program:\n%w", ve)
		}
		return nil, fmt.Errorf("nat66attach: load and pin nat66 objects: %w", loadErr)
	}
	return &loaded, nil
}

// unpinIncompatibleMaps mirrors internal/plumbing/ebpf/edgeattach's
// identical helper -- see that function's doc comment.
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

// Attach attaches program to ifaceName's XDP hook in native driver mode,
// returning the link for the caller to hold open and close on shutdown. See the
// package doc comment for why native mode is required and why no pinning or
// re-attachment is needed.
func Attach(program *ebpf.Program, ifaceName string) (link.Link, error) {
	if program == nil {
		return nil, errors.New("nat66attach: program is nil")
	}

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("nat66attach: find link %q: %w", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"nat66attach: attach XDP program to %q in native/driver mode: %w "+
				"(this program requires native XDP support -- generic/SKB mode is not attempted, "+
				"see this package's doc comment)",
			ifaceName, err,
		)
	}
	return xdpLink, nil
}
