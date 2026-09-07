// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bond holds the netlink-view-agnostic logic for recognizing a Linux
// bonding master and enumerating its slaves.
//
// It exists so the two attach paths share one implementation of "is this a bond,
// and if so what are its slaves". The TC-BPF ingress path attaches to both the
// master and its slaves, ingress classification on a bond happening on the
// slaves; the XDP path attaches to the slaves only, native XDP against a bonding
// master being unreliable.
//
// Each caller keeps its own netlink override vars for testability, and this
// package takes plain link values rather than function vars, so it carries no
// test-only indirection.
package bond

import "github.com/vishvananda/netlink"

// LinkType is the vishvananda/netlink Link.Type() value reported for a
// Linux bonding master.
const LinkType = "bond"

// IsMaster reports whether link is a Linux bonding master.
func IsMaster(link netlink.Link) bool {
	return link.Type() == LinkType
}

// SlaveNames returns the names of every link in links enslaved to master,
// meaning those whose master index equals master's own, in whatever order links
// is in. Returns nil when master has no slaves there.
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
