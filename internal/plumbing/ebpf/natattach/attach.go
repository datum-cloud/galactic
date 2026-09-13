// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natattach

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

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// PinDir is the default bpffs directory every NAT66 map is pinned under,
// deliberately distinct from every other datapath's, so each is fully
// independent under bpffs even where map names do not collide.
const PinDir = "/sys/fs/bpf/galactic-nat"

// Load loads the compiled NAT66 object with every map pinned under pinDir. A
// map already pinned there by a previous process is reused as-is. See the
// package doc comment for why, unlike its sibling, there is no kernel preflight
// check here.
func Load(pinDir string) (*natprog.NatObjects, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("natattach: remove memlock rlimit: %w", err)
	}
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("natattach: create bpf map pin directory %q: %w", pinDir, err)
	}

	spec, err := natprog.LoadNat()
	if err != nil {
		return nil, fmt.Errorf("natattach: load compiled nat66 collection spec: %w", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	var loaded natprog.NatObjects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	loadErr := spec.LoadAndAssign(&loaded, opts)
	if loadErr != nil && errors.Is(loadErr, ebpf.ErrMapIncompatible) {
		// Every map here is either control-plane-owned and reconstructable,
		// the shard config being rewritten at process startup, or
		// datapath-owned and self-managing, the connection table being an
		// LRU that self-evicts and the drop counters a pure array. A stale
		// pin from an incompatible layout is safe to recreate.
		slog.Warn("natattach: pinned eBPF map incompatible with the newly compiled map spec, recreating "+
			"(control-plane state will repopulate at next startup)", "pinDir", pinDir, "err", loadErr)
		if unpinErr := unpinIncompatibleMaps(spec, pinDir); unpinErr != nil {
			return nil, fmt.Errorf("natattach: recreate incompatible pinned maps: %w", unpinErr)
		}
		loadErr = spec.LoadAndAssign(&loaded, opts)
	}
	if loadErr != nil {
		var ve *ebpf.VerifierError
		if errors.As(loadErr, &ve) {
			return nil, fmt.Errorf("natattach: verifier rejected nat_ingress program:\n%w", ve)
		}
		return nil, fmt.Errorf("natattach: load and pin nat66 objects: %w", loadErr)
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

// PopulateProgArray fills the nat_progs tail-call array with the four
// translation leaves the dispatcher hands packets to.
//
// It must run before Attach. The dispatcher never modifies a packet, so a tail
// call into an empty slot falls through to XDP_PASS and the packet leaves
// untranslated rather than half-translated -- safe, but it would mean traffic
// silently bypassing the shard for as long as the gap lasted. Populating first
// closes that window entirely instead of narrowing it.
func PopulateProgArray(objs *natprog.NatObjects) error {
	slots := map[uint32]*ebpf.Program{
		natprog.ProgNAT66Forward: objs.Nat66Forward,
		natprog.ProgNAT66Return:  objs.Nat66Return,
		natprog.ProgNAT64Forward: objs.Nat64Forward,
		natprog.ProgNAT64Return:  objs.Nat64Return,
	}
	for slot, prog := range slots {
		if prog == nil {
			return fmt.Errorf("natattach: nat_progs slot %d has no loaded program", slot)
		}
		if err := objs.NatProgs.Put(slot, prog); err != nil {
			return fmt.Errorf("natattach: populate nat_progs slot %d: %w", slot, err)
		}
	}
	return nil
}

// Attach attaches program to ifaceName's XDP hook in native driver mode,
// returning the link for the caller to hold open and close on shutdown. See the
// package doc comment for why native mode is required and why no pinning or
// re-attachment is needed.
func Attach(program *ebpf.Program, ifaceName string) (link.Link, error) {
	if program == nil {
		return nil, errors.New("natattach: program is nil")
	}

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("natattach: find link %q: %w", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"natattach: attach XDP program to %q in native/driver mode: %w "+
				"(this program requires native XDP support -- generic/SKB mode is not attempted, "+
				"see this package's doc comment)",
			ifaceName, err,
		)
	}
	return xdpLink, nil
}
