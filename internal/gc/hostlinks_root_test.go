// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// addUpTap creates vpc's VRF and a tap for attachment att owned by owner,
// enslaved to it, and brings the tap up so routes can use it.
func addUpTap(vpc, att, owner string) error {
	if err := vrf.EnsureAndEnslave(vpc, func(*netlink.Vrf) error {
		_, err := tap.Add(vpc, att, owner, 1500)
		return err
	}); err != nil {
		return err
	}
	link, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(vpc, att))
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// TestLeftoverTapNoLongerBlocksReusedAddress replays the failure end to end
// on a real kernel. A sandbox's tap on attachment a1 holds the pod-subnet
// route for an address, its sandbox is gone, and the control plane gives the
// same address to attachment a2: a2's host gateway is refused while a1's tap
// survives. One GC pass over a1's dead advertisement removes the tap, the
// kernel takes its route with it, and a2's host gateway then installs.
func TestLeftoverTapNoLongerBlocksReusedAddress(t *testing.T) {
	requireRoot(t)
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	_, subnet, err := net.ParseCIDR("2001:db8:0:1::5:0:0/96")
	if err != nil {
		t.Fatal(err)
	}
	res := &cniipam.IPAMResult{IPv6Subnet: subnet, IPv6Gateway: net.ParseIP("2001:db8:0:1::1")}
	k8s := deadAttachmentClient(t)

	err = nsObj.Do(func(ns.NetNS) error {
		if err := addUpTap(reclaimVPC, "a1", deadSandbox); err != nil {
			return fmt.Errorf("dead sandbox's tap: %w", err)
		}
		if err := hostgw.RestoreHostGateway(reclaimVPC, "a1", res, nil); err != nil {
			return fmt.Errorf("dead sandbox's route: %w", err)
		}
		if err := addUpTap(reclaimVPC, "a2", liveSandbox); err != nil {
			return fmt.Errorf("new sandbox's tap: %w", err)
		}
		if err := hostgw.RestoreHostGateway(reclaimVPC, "a2", res, nil); err == nil {
			return errors.New("new sandbox's route installed over a leftover tap's, want the conflict refused")
		}

		orphans, err := CollectOrphanedCRDs(context.Background(), k8s, edgeTestNamespace, edgeTestNode, using())
		if err != nil {
			return err
		}
		gcRes := RemoveOrphanedCRDs(context.Background(), k8s, orphans, using())
		if gcRes.Errors != 0 || gcRes.HostLinksRemoved != 1 {
			return fmt.Errorf("GC pass = %+v, want the dead tap removed", gcRes)
		}
		if _, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(reclaimVPC, "a2")); err != nil {
			return fmt.Errorf("new sandbox's tap after GC: %w", err)
		}
		if err := hostgw.RestoreHostGateway(reclaimVPC, "a2", res, nil); err != nil {
			return fmt.Errorf("new sandbox's route after GC: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
