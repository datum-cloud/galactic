// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"fmt"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

func TestGatewayReplyRedirect_KernelReconcileAndCleanup(t *testing.T) {
	requireRoot(t)
	const vpc = "2"
	prefix := mustParseCIDR(t, "fd42::/48")
	SetGatewayAddressAssignment(prefix, "reply-test")
	t.Cleanup(func() { SetGatewayAddressAssignment(nil, "") })
	addr, err := DeriveGatewayAddress(prefix, vpc, "reply-test")
	if err != nil {
		t.Fatal(err)
	}

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	if err := nsObj.Do(func(_ ns.NetNS) error {
		eth0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: primaryPodInterface}}
		if err := netlink.LinkAdd(eth0); err != nil {
			return fmt.Errorf("add eth0: %w", err)
		}
		eth0Link, err := netlink.LinkByName(primaryPodInterface)
		if err != nil {
			return fmt.Errorf("look up eth0: %w", err)
		}
		inner := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "reply-inner"}, PeerName: "reply-peer"}
		if err := netlink.LinkAdd(inner); err != nil {
			return fmt.Errorf("add veth: %w", err)
		}
		innerLink, err := netlink.LinkByName(inner.Attrs().Name)
		if err != nil {
			return fmt.Errorf("look up veth: %w", err)
		}
		for i := 0; i < 2; i++ {
			if err := ensureGatewayReplyRedirect(addr, innerLink); err != nil {
				return fmt.Errorf("ensure redirect #%d: %w", i+1, err)
			}
		}
		filters, err := gatewayReplyFilters(eth0Link)
		if err != nil {
			return err
		}
		if len(filters) != 1 || !filters[0].DestIP.Equal(addr) {
			return fmt.Errorf("filters after repeated ensure = %v, want one for %s", filters, addr)
		}
		action, ok := filters[0].Actions[0].(*netlink.MirredAction)
		if !ok || action.Ifindex != innerLink.Attrs().Index || action.MirredAction != netlink.TCA_INGRESS_REDIR {
			return fmt.Errorf("reply redirect action = %v, want ingress redirect to %d", filters[0].Actions, innerLink.Attrs().Index)
		}
		if err := removeGatewayReplyRedirect(vpc); err != nil {
			return err
		}
		filters, err = gatewayReplyFilters(eth0Link)
		if err != nil {
			return err
		}
		if len(filters) != 0 {
			return fmt.Errorf("filters after removal = %v, want none", filters)
		}
		return removeGatewayReplyRedirect(vpc)
	}); err != nil {
		t.Fatal(err)
	}
}
