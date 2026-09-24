// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/natsrcfiltermap"
)

// setupSourceFilter writes the SRv6 source filter's mode and numbers this
// shard's uplinks into slots, in configuration order, so allow-list entries
// can bind a prefix to the uplinks it is reachable through. It leaves the
// allow-list and its populated flag to their own reconciler, so until that
// has run the datapath applies only its structural source checks.
func setupSourceFilter(cfg *config.NATConfig, filter *natsrcfiltermap.Filter) error {
	mode, err := natsrcfiltermap.ParseMode(cfg.SRv6SourceFilter)
	if err != nil {
		return err
	}
	slots, err := uplinkSlots(cfg.UplinkInterfaces, linkIndexByName)
	if err != nil {
		return err
	}
	if err := filter.SyncUplinkSlots(slots); err != nil {
		return err
	}
	return filter.SetMode(mode)
}

// uplinkSlots assigns slot N to the Nth interface in ifaces, keyed by the
// ifindex ifindexOf resolves it to. It returns an error when an interface does
// not resolve or there are more interfaces than slots.
func uplinkSlots(ifaces []string, ifindexOf func(string) (int, error)) (map[uint32]uint8, error) {
	if len(ifaces) > int(natprog.SrcFilterMaxSlot)+1 {
		return nil, fmt.Errorf("%d uplink interfaces exceed the source filter's %d slots",
			len(ifaces), int(natprog.SrcFilterMaxSlot)+1)
	}
	slots := make(map[uint32]uint8, len(ifaces))
	for i, name := range ifaces {
		ifindex, err := ifindexOf(name)
		if err != nil {
			return nil, fmt.Errorf("resolve uplink interface %q: %w", name, err)
		}
		slots[uint32(ifindex)] = uint8(i)
	}
	return slots, nil
}

func linkIndexByName(name string) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, err
	}
	return link.Attrs().Index, nil
}
