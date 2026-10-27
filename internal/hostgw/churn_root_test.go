// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostgw

import (
	"fmt"
	"net"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/nldump/nldumptest"
)

// churnPasses is how many passes the churn test runs at least, enough for a
// single-attempt link listing to meet an interruption.
const churnPasses = 200

// TestEnsureTapGuestNeighbors_UnderLinkChurn requires the tap guest neighbor
// sweep to find and resolve a VPC tap's guest on every pass while links are
// added and removed on the node. The guest's neighbor entry is already
// present, so a pass that finds the tap resolves it without soliciting.
func TestEnsureTapGuestNeighbors_UnderLinkChurn(t *testing.T) {
	requireRoot(t)
	const table = 1000
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	err = nsObj.Do(func(ns.NetNS) error {
		vrfLink := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "churnvrf"}, Table: table}
		if err := netlink.LinkAdd(vrfLink); err != nil {
			return fmt.Errorf("add VRF: %w", err)
		}
		tap := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "churntap"}, Mode: netlink.TUNTAP_MODE_TAP}
		if err := netlink.LinkAdd(tap); err != nil {
			return fmt.Errorf("add tap: %w", err)
		}
		if err := netlink.LinkSetMaster(tap, vrfLink); err != nil {
			return fmt.Errorf("enslave tap: %w", err)
		}
		for _, l := range []netlink.Link{vrfLink, tap} {
			if err := netlink.LinkSetUp(l); err != nil {
				return fmt.Errorf("set %s up: %w", l.Attrs().Name, err)
			}
		}
		guest := mustParseCIDR(t, "fd20:40:ff01::/96")
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: tap.Attrs().Index, Dst: guest, Table: table}); err != nil {
			return fmt.Errorf("add guest route: %w", err)
		}
		return netlink.NeighAdd(&netlink.Neigh{
			LinkIndex: tap.Attrs().Index, Family: netlink.FAMILY_V6, State: netlink.NUD_PERMANENT,
			IP: guest.IP, HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	nldumptest.Churn(t, nsObj)

	passes := nldumptest.UntilInterrupted(t, nsObj, []string{nldumptest.KindLink}, churnPasses, func() error {
		if resolved, pending := EnsureTapGuestNeighbors(); resolved != 1 || pending != 0 {
			return fmt.Errorf("EnsureTapGuestNeighbors() = (%d, %d), want (1, 0)", resolved, pending)
		}
		return nil
	})
	t.Logf("%d passes", passes)
}
