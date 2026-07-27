// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"
)

// addTap creates a tap device with the given name, MTU, and owner uid/gid.
// Callers must already be running inside the target network namespace (see
// ns.WithNetNSPath in ops_add.go) — addTap never enters a namespace itself.
// Idempotent: if a tap device with this name already exists (crash-recovery
// or a retried ADD), its attributes are left as-is rather than recreated,
// mirroring internal/cni/tap.Add's repair behavior for a simpler case (no
// VRF enslavement here).
func addTap(name string, mtu int, ownerUID, ownerGID uint32) (netlink.Link, error) {
	if existing, err := netlink.LinkByName(name); err == nil {
		slog.Warn("vmtap: found existing tap from a previous ADD attempt, reusing", "tap", name)
		return existing, nil
	}

	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu,
		},
		Mode:  netlink.TUNTAP_MODE_TAP,
		Flags: netlink.TUNTAP_ONE_QUEUE | netlink.TUNTAP_VNET_HDR,
		Owner: ownerUID,
		Group: ownerGID,
	}

	if err := netlink.LinkAdd(tap); err != nil {
		return nil, fmt.Errorf("create tap %q: %w", name, err)
	}
	slog.Debug("vmtap: tap created", "tap", name, "mtu", mtu, "ownerUID", ownerUID, "ownerGID", ownerGID)

	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("find created tap %q: %w", name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("bring up tap %q: %w", name, err)
	}

	return link, nil
}

// deleteTap removes the named tap device. Idempotent — a missing device is
// not an error, per the CNI spec's DEL idempotency requirement.
func deleteTap(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		slog.Debug("vmtap: tap already gone, nothing to delete", "tap", name)
		return nil
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete tap %q: %w", name, err)
	}
	slog.Debug("vmtap: tap deleted", "tap", name)
	return nil
}
