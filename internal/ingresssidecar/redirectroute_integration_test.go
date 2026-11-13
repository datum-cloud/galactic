// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"fmt"
	"net"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/vrf"
)

// mainTableRedirect returns the ifindex the main-table route for prefix leaves
// through, or 0 when there is none.
func mainTableRedirect(prefix *net.IPNet) (int, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Dst: prefix, Table: unix.RT_TABLE_MAIN},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, err
	}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == prefix.String() {
			return r.LinkIndex, nil
		}
	}
	return 0, nil
}

// TestRemoveRedirectRoute_KeepsAnotherVPCsRoute: two VPCs carry the same
// backend address, as when IPAM hands a deleted Network's subnet to the next
// one. The live VPC's redirect replaced the deleted VPC's, so tearing down the
// deleted VPC's route must leave the live one alone. Before the fix, the delete
// matched the destination only and removed the live VPC's route.
func TestRemoveRedirectRoute_KeepsAnotherVPCsRoute(t *testing.T) {
	requireRoot(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	const (
		oldTable = vrf.SidecarTableIDBase + 12
		newTable = vrf.SidecarTableIDBase + 13
		gone     = vrf.SidecarTableIDBase + 14 // no VRF device uses it
	)
	backend := mustPrefix(t, "fd20:0:1e::1:0:0")

	err = nsObj.Do(func(_ ns.NetNS) error {
		var newIndex int
		for _, v := range []struct {
			name  string
			table uint32
		}{{"ivstestold", oldTable}, {"ivstestnew", newTable}} {
			link := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: v.name}, Table: v.table}
			if err := netlink.LinkAdd(link); err != nil {
				return fmt.Errorf("add VRF %s: %w", v.name, err)
			}
			if err := netlink.LinkSetUp(link); err != nil {
				return fmt.Errorf("set VRF %s up: %w", v.name, err)
			}
			newIndex = link.Attrs().Index
		}

		if err := ensureRedirectRoute(backend, oldTable); err != nil {
			return err
		}
		if err := ensureRedirectRoute(backend, newTable); err != nil {
			return err
		}

		if err := removeRedirectRoute(backend, oldTable); err != nil {
			return fmt.Errorf("remove deleted VPC's route: %w", err)
		}
		if got, err := mainTableRedirect(backend); err != nil || got != newIndex {
			return fmt.Errorf("after removing the deleted VPC's route: redirect via ifindex %d (err %w), want live VPC's %d",
				got, err, newIndex)
		}

		if err := removeRedirectRoute(backend, gone); err != nil {
			return fmt.Errorf("remove for a table with no VRF: %w", err)
		}
		if got, err := mainTableRedirect(backend); err != nil || got != newIndex {
			return fmt.Errorf("after removal for a table with no VRF: redirect via ifindex %d (err %w), want %d",
				got, err, newIndex)
		}

		if err := removeRedirectRoute(backend, newTable); err != nil {
			return fmt.Errorf("remove live VPC's route: %w", err)
		}
		if got, err := mainTableRedirect(backend); err != nil || got != 0 {
			return fmt.Errorf("after removing the owner's route: redirect via ifindex %d (err %w), want none", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
