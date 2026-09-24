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

	"go.datum.net/galactic/internal/plumbing/bond"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// linkByNameFn and linkListFn are override points, as elsewhere in this
// codebase, so ResolveTargets' tests can substitute a fake netlink view without
// touching the host network stack.
var (
	linkByNameFn = netlink.LinkByName
	linkListFn   = netlink.LinkList
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

// ResolveTargets resolves the configured uplink names to the interface names
// Attach should actually attach the XDP program to.
//
// An uplink that is not a bonding master resolves to itself. A bonding master
// resolves to its slaves instead, the master excluded, for the reason the edge
// attach package's ResolveTargets gives: native XDP against a bonding master is
// not reliable, and some kernels' bonding driver accepts it only by forwarding
// it to slaves whose support nothing here has checked. A master with no slaves
// is an error, since it would leave that uplink with no attachment at all.
//
// A name listed twice, or a slave listed alongside its own master, resolves to
// one target: attaching the same program to one hook twice fails outright.
func ResolveTargets(ifaceNames []string) ([]string, error) {
	var (
		targets []string
		links   []netlink.Link
	)
	seen := make(map[string]bool)
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			targets = append(targets, name)
		}
	}

	for _, ifaceName := range ifaceNames {
		iface, err := linkByNameFn(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("natattach: find link %q: %w", ifaceName, err)
		}
		if !bond.IsMaster(iface) {
			add(ifaceName)
			continue
		}

		if links == nil {
			if links, err = linkListFn(); err != nil {
				return nil, fmt.Errorf("natattach: enumerate slaves of bonding master %q: %w", ifaceName, err)
			}
		}
		slaves := bond.SlaveNames(iface, links)
		if len(slaves) == 0 {
			return nil, fmt.Errorf(
				"natattach: bonding master %q has no slave interfaces to attach the XDP program to", ifaceName)
		}
		for _, slave := range slaves {
			add(slave)
		}
	}
	return targets, nil
}

// Attach attaches program to the XDP hook of every interface in ifaceNames, in
// native driver mode, returning the resulting link for each in the same order
// for the caller to hold open and close on shutdown. Callers resolve ifaceNames
// through ResolveTargets first, so a bonding master never reaches here. See the
// package doc comment for why native mode is required and why no pinning or
// re-attachment is needed.
//
// Every fabric uplink is attached, not only the one a shard node's traffic uses
// today: a packet arriving on an interface this program is not attached to
// reaches no translation at all and is forwarded untranslated and uncounted.
// An empty list is rejected rather than treated as "attach nothing", which
// would produce exactly that silence across the whole node.
//
// If attaching one interface fails partway through, every link already attached
// in this call is closed before returning, so a caller that gets an error holds
// no partial attachment to clean up. Attachment is therefore all-or-nothing: a
// shard that cannot claim every uplink it was given fails to start rather than
// running with a hole in its coverage.
func Attach(program *ebpf.Program, ifaceNames []string) ([]link.Link, error) {
	if program == nil {
		return nil, errors.New("natattach: program is nil")
	}
	if len(ifaceNames) == 0 {
		return nil, errors.New("natattach: no interfaces to attach to")
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
