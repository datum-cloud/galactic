// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
)

func hasLocalRoute(addr net.IP) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V6,
		&netlink.Route{Type: unix.RTN_LOCAL, Table: unix.RT_TABLE_UNSPEC},
		netlink.RT_FILTER_TYPE|netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, fmt.Errorf("list local routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(addr) {
			return true, nil
		}
	}
	return false, nil
}

func waitForLocalRoute(addr net.IP, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ok, err := hasLocalRoute(addr)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("no local route for the gateway address")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestEnsureGatewayAddress_KeepsLocalRouteWhenRepeated pins that running
// ensureGatewayAddress again once the address has finished duplicate address
// detection does not strip its local route. Replacing the address does, and
// what remains is a connected route: the VRF forwards traffic for the gateway
// instead of delivering it.
func TestEnsureGatewayAddress_KeepsLocalRouteWhenRepeated(t *testing.T) {
	requireRoot(t)
	t.Cleanup(func() { SetGatewayAddressAssignment(nil, "") })
	SetGatewayAddressAssignment(mustParseCIDR(t, "fd30:e2e::/32"), "worker-1")

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	const vpc = "2"
	const inner = "ivstest"

	err = nsObj.Do(func(_ ns.NetNS) error {
		vrfLink := &netlink.Vrf{
			LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpc)},
			Table:     7,
		}
		if err := netlink.LinkAdd(vrfLink); err != nil {
			return fmt.Errorf("add VRF: %w", err)
		}
		if err := netlink.LinkSetUp(vrfLink); err != nil {
			return fmt.Errorf("set VRF up: %w", err)
		}
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: inner}, PeerName: "ivptest"}
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("add veth: %w", err)
		}
		innerLink, err := netlink.LinkByName(inner)
		if err != nil {
			return fmt.Errorf("look up %q: %w", inner, err)
		}
		if err := netlink.LinkSetMaster(innerLink, vrfLink); err != nil {
			return fmt.Errorf("enslave: %w", err)
		}
		for _, name := range []string{inner, "ivptest"} {
			l, err := netlink.LinkByName(name)
			if err != nil {
				return fmt.Errorf("look up %q: %w", name, err)
			}
			if err := netlink.LinkSetUp(l); err != nil {
				return fmt.Errorf("set %q up: %w", name, err)
			}
		}

		prefix, nodeID := gatewayAddressAssignment()
		addr, err := DeriveGatewayAddress(prefix, vpc, nodeID)
		if err != nil {
			return err
		}

		if err := ensureGatewayAddress(vpc, inner); err != nil {
			return fmt.Errorf("first ensureGatewayAddress: %w", err)
		}
		if err := waitForLocalRoute(addr, 10*time.Second); err != nil {
			return fmt.Errorf("after the first call: %w", err)
		}

		if err := ensureGatewayAddress(vpc, inner); err != nil {
			return fmt.Errorf("second ensureGatewayAddress: %w", err)
		}
		ok, err := hasLocalRoute(addr)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("the second call removed the gateway address's local route")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
