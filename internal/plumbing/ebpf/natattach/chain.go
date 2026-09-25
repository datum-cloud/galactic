// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natattach

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
)

// EdgeChainMapPath is where the edge gateway pins xdp_chain: the edge attach
// package's PinDir joined with the map's name, spelled out here so this binary
// does not link the gateway's datapath to learn one path. edgeattach's tests
// hold the two in step.
const EdgeChainMapPath = "/sys/fs/bpf/galactic-edge/xdp_chain"

// chainSlot is xdp_chain's one slot, EDGE_CHAIN_SLOT in edgedsr.c.
const chainSlot = uint32(0)

// AttachChain installs program in the edge gateway's xdp_chain slot, pinned at
// mapPath, so the gateway's programs hand it every packet they do not claim.
//
// This is how the shard runs on an edge node. The gateway already holds the
// native XDP hook on the interfaces the shard needs, and an interface takes
// one native program, so a second Attach there fails outright. Chained, the
// shard sees exactly the traffic it would have seen attached: the gateway's
// claimed set (VIP destination or source) is disjoint from the shard's (shard
// SID or masquerade address destination).
//
// There is no link to hold and none is returned. The slot keeps program alive
// on its own, across this process's exit, and the next process's AttachChain
// replaces it in place, with no window where the shard claims nothing. A slot
// holding a program whose shard has since been cleared is harmless: an
// unprogrammed shard claims no packet.
//
// A missing map means the gateway has not loaded yet, and is returned as an
// error wrapping ebpf's not-exist error for the caller to retry.
func AttachChain(program *ebpf.Program, mapPath string) error {
	if program == nil {
		return errors.New("natattach: program is nil")
	}
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("natattach: open edge chain map %q: %w", mapPath, err)
	}
	defer m.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use

	if m.Type() != ebpf.ProgramArray {
		return fmt.Errorf("natattach: edge chain map %q is a %s, not a program array", mapPath, m.Type())
	}
	// The kernel checks program against the array's owner -- type, JIT state,
	// frags support and expected attach type -- and refuses a mismatch with a
	// bare EINVAL, so say which check that is.
	if err := m.Put(chainSlot, program); err != nil {
		return fmt.Errorf("natattach: install program in edge chain map %q "+
			"(EINVAL here means the program is incompatible with the gateway's): %w", mapPath, err)
	}
	return nil
}

// ChainHolds reports whether the xdp_chain slot pinned at mapPath currently
// holds program. It is false, not an error, for an empty slot or a slot
// holding another program -- the state a gateway restart that recreated the
// map leaves behind, and what a caller re-asserting the slot looks for.
func ChainHolds(program *ebpf.Program, mapPath string) (bool, error) {
	info, err := program.Info()
	if err != nil {
		return false, fmt.Errorf("natattach: read program info: %w", err)
	}
	want, ok := info.ID()
	if !ok {
		return false, errors.New("natattach: kernel reports no program ID")
	}

	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return false, fmt.Errorf("natattach: open edge chain map %q: %w", mapPath, err)
	}
	defer m.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use

	// A program array read from user space yields the installed program's ID.
	var got uint32
	if err := m.Lookup(chainSlot, &got); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("natattach: read edge chain map %q: %w", mapPath, err)
	}
	return ebpf.ProgramID(got) == want, nil
}

// WarnUnhookedUplinks logs every one of ifaceNames that carries no XDP
// program. Chained, the shard sees only what the gateway's programs see, so an
// uplink the gateway is not attached to is one whose traffic this shard never
// translates -- the same silent gap an unattached uplink is in direct mode. It
// only warns: which interfaces the gateway attaches to is its own
// configuration, not this process's.
func WarnUnhookedUplinks(ifaceNames []string) {
	for _, name := range ifaceNames {
		l, err := linkByNameFn(name)
		if err != nil {
			slog.Warn("natattach: cannot inspect uplink for an XDP program", "interface", name, "err", err)
			continue
		}
		if xdp := l.Attrs().Xdp; xdp == nil || !xdp.Attached {
			slog.Warn("natattach: uplink carries no XDP program, so the chained shard sees none of its traffic; "+
				"the edge gateway is not attached to it", "interface", name)
		}
	}
}
