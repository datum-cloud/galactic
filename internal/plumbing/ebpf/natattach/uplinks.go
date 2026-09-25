// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natattach

import (
	"errors"
	"fmt"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

// detectUplinksFn is an override point so ResolveUplinks' tests can substitute
// a fake route view without touching the host network stack. The netlink
// override points ResolveTargets uses (linkByNameFn, linkListFn) live in
// attach.go.
var detectUplinksFn = attach.DetectUplinks

// ResolveUplinks returns the interfaces Attach should attach the egress
// translation program to.
//
// A non-empty override is used as given. Otherwise the uplinks are
// auto-detected with the same derivation the CNI's SRv6 datapath uses
// (attach.DetectUplinks), so the shard and the CNI on one node converge on the
// same physical uplinks with no per-node configuration. The override exists for
// a multi-homed node where that derivation cannot be confident.
//
// Either way, every name then passes through ResolveTargets: a bonding master
// resolves to its slaves and never to itself, native XDP on a master being
// unreliable.
//
// An empty result is an error. The datapath claims a packet only on an
// interface it is attached to, so too few uplinks is a silent blackhole rather
// than a degraded mode.
func ResolveUplinks(override []string) ([]string, error) {
	names := override
	if len(names) == 0 {
		detected, err := detectUplinksFn()
		if err != nil {
			return nil, fmt.Errorf("natattach: auto-detect uplinks: %w", err)
		}
		names = detected
	}

	targets, err := ResolveTargets(names)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("natattach: no uplink interfaces resolved")
	}
	return targets, nil
}
