// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bond holds the pure, netlink-view-agnostic logic for recognizing
// a Linux bonding master and enumerating its slave interfaces. It exists so
// internal/plumbing/ebpf/attach (the CNI's TC-BPF ingress path, which
// attaches to both a bond master and its slaves -- ingress tc/eBPF
// classification on a bonded interface happens on the slaves, not the
// master) and internal/plumbing/ebpf/edgeattach (the gateway's XDP path,
// which must attach to the slaves only -- native-mode XDP cannot attach to
// a bonding master at all, since bonding doesn't implement ndo_bpf) share
// one implementation of "is this a bond, and if so what are its slaves"
// instead of each maintaining its own copy. See
// internal/plumbing/ebpf/edgeattach.ResolveTargets' own doc comment for the
// more precise statement of why XDP can't rely on the bond master itself:
// it isn't simply "bonding never implements ndo_bpf" on every kernel, but
// attaching to the master is never something this codebase relies on
// working either way.
//
// Each caller keeps its own package-level netlink override vars for
// testability (matching the existing linkByNameFn/linkListFn pattern in
// both packages above); this package takes plain netlink.Link/[]netlink.Link
// values rather than function vars of its own, so it has no test-only
// indirection to carry.
package bond

import "github.com/vishvananda/netlink"

// LinkType is the vishvananda/netlink Link.Type() value reported for a
// Linux bonding master.
const LinkType = "bond"

// IsMaster reports whether link is a Linux bonding master.
func IsMaster(link netlink.Link) bool {
	return link.Type() == LinkType
}

// SlaveNames returns the names of every link in links enslaved to master
// (i.e. whose MasterIndex, populated from netlink's IFLA_MASTER attribute,
// equals master's own index), in whatever order links itself is in. Returns
// nil if master has no slaves in links.
func SlaveNames(master netlink.Link, links []netlink.Link) []string {
	masterIndex := master.Attrs().Index
	var slaves []string
	for _, l := range links {
		if l.Attrs().MasterIndex == masterIndex {
			slaves = append(slaves, l.Attrs().Name)
		}
	}
	return slaves
}
