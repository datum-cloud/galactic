// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create a test network namespace and install routes; re-run via sudo")
	}
}

// TestRouteEgressAddRejectsUnspecifiedGateway verifies that RouteEgressAdd
// refuses to install a seg6 encap route when it isn't handed a real SRv6 SID.
// This is the defense-in-depth backstop for the bug where a missing/zero SID
// upstream (e.g. an EVPN path with no Prefix-SID attribute) got fed straight
// through and silently installed a route encapsulating to
// "::ffff:0.0.0.0" — a route to nowhere — instead of failing loudly. The
// check must run before any netlink call so this test needs no privileges.
func TestRouteEgressAddRejectsUnspecifiedGateway(t *testing.T) {
	_, prefix, err := net.ParseCIDR("172.20.20.2/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	tests := []struct {
		name    string
		gateway net.IP
	}{
		{name: "nil gateway", gateway: nil},
		{name: "IPv4 zero", gateway: net.IPv4zero},
		{name: "IPv4-mapped IPv6 zero (::ffff:0.0.0.0)", gateway: net.ParseIP("0.0.0.0").To16()},
		{name: "IPv6 zero", gateway: net.IPv6unspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := RouteEgressAdd(prefix, tt.gateway, 1); err == nil {
				t.Errorf("RouteEgressAdd(%v) = nil error, want an error rejecting the unusable gateway", tt.gateway)
			}
		})
	}
}

// TestRouteEgressAdd_InstallsForBothPrefixFamilies covers the regression
// where every IPv6 VPC prefix's egress route failed to install with
// "invalid argument": RouteEgressAdd unconditionally attached the resolved
// next-hop via netlink.Route.Via, which the kernel only accepts when Via's
// address family differs from Dst's. An IPv4 VPC prefix egressing over the
// IPv6 SRv6 underlay needs exactly that cross-family Via -- and did already
// work -- but an IPv6 VPC prefix's next-hop shares Dst's family and must go
// through the plain Gw field instead, or the kernel rejects the route
// outright. This test installs one route of each prefix family against a
// real kernel routing table and asserts both succeed, with the outcome
// (Gw vs Via) matching each family's requirement.
func TestRouteEgressAdd_InstallsForBothPrefixFamilies(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName  = "srv6test0"
		ifaceAddr  = "2001:db8:1::1/64"
		sidRoute   = "2001:db8:9::9/128" // reachable via ifaceAddr's subnet
		sidGateway = "2001:db8:1::2"     // on-link next-hop for sidRoute
		sid        = "2001:db8:9::9"     // the resolved SRv6 SID (gateway arg)
		table      = 100
	)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}}
		if err := netlink.LinkAdd(dummy); err != nil {
			return fmt.Errorf("add dummy link: %w", err)
		}
		if err := netlink.LinkSetUp(dummy); err != nil {
			return fmt.Errorf("set link up: %w", err)
		}
		addr, err := netlink.ParseAddr(ifaceAddr)
		if err != nil {
			return fmt.Errorf("parse addr: %w", err)
		}
		if err := netlink.AddrAdd(dummy, addr); err != nil {
			return fmt.Errorf("add addr: %w", err)
		}
		// A multi-hop route to the SID via an on-link next-hop, so
		// RouteGet(sid) resolves with Gw set -- exactly the shape
		// RouteEgressAdd expects from a real BGP-learned SRv6 SID.
		_, sidDst, err := net.ParseCIDR(sidRoute)
		if err != nil {
			return fmt.Errorf("parse SID route: %w", err)
		}
		route := &netlink.Route{
			LinkIndex: dummy.Attrs().Index,
			Dst:       sidDst,
			Gw:        net.ParseIP(sidGateway),
		}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("add route to SID: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	gateway := net.ParseIP(sid)

	tests := []struct {
		name    string
		prefix  string
		wantVia bool // Via must be set (cross-family: IPv4 prefix, IPv6 next-hop)
		wantGw  bool // Gw must be set (same-family: IPv6 prefix, IPv6 next-hop)
	}{
		{name: "IPv4 VPC prefix uses Via (cross-family)", prefix: "172.20.20.2/32", wantVia: true},
		{name: "IPv6 VPC prefix uses Gw (same-family)", prefix: "fd20:10:ff02::/96", wantGw: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, prefix, err := net.ParseCIDR(tt.prefix)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", tt.prefix, err)
			}

			err = nsObj.Do(func(_ ns.NetNS) error {
				return RouteEgressAdd(prefix, gateway, table)
			})
			if err != nil {
				t.Fatalf("RouteEgressAdd(%s) = %v, want success", tt.prefix, err)
			}

			var installed *netlink.Route
			err = nsObj.Do(func(_ ns.NetNS) error {
				family := netlink.FAMILY_V6
				if prefix.IP.To4() != nil {
					family = netlink.FAMILY_V4
				}
				routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
				if err != nil {
					return err
				}
				for i := range routes {
					if routes[i].Dst != nil && routes[i].Dst.String() == prefix.String() {
						installed = &routes[i]
						return nil
					}
				}
				return fmt.Errorf("no route to %s found in table %d", prefix, table)
			})
			if err != nil {
				t.Fatalf("verify installed route: %v", err)
			}

			if tt.wantVia && installed.Via == nil {
				t.Errorf("installed route for %s has no Via, want cross-family Via set", tt.prefix)
			}
			if tt.wantGw && installed.Gw == nil {
				t.Errorf("installed route for %s has no Gw, want same-family Gw set", tt.prefix)
			}
		})
	}
}

// TestRouteEgressDel_RemovesInstalledRoute is the regression test for a bug
// found while building datum-cloud/enhancements#865's egress route
// reconciler: every call to RouteEgressDel failed with "EncodeSEG6Encap: No
// Segment in srh", because it set Encap to an empty &netlink.SEG6Encap{}
// on the delete request, and netlink.RouteDel's shared encoding path
// (routeHandle, used by every Route* function regardless of message type)
// tries to encode whatever Encap is set to -- unconditionally rejecting a
// SEG6Encap with zero Segments. This was a real, previously-untested bug in
// already-shipped production code: internal/runtime/gobgp/monitor.go's BGP
// path-withdrawal handler has called this function since it was written,
// with nothing to notice every call was actually failing.
func TestRouteEgressDel_RemovesInstalledRoute(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName = "srv6del0"
		ifaceAddr = "2001:db8:2::1/64"
		sidRoute  = "2001:db8:9::9/128"
		sidGw     = "2001:db8:2::2"
		sid       = "2001:db8:9::9"
		prefix    = "fd20:10:ff03::/96"
		table     = 101
	)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	_, dst, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}}
		if err := netlink.LinkAdd(dummy); err != nil {
			return fmt.Errorf("add dummy link: %w", err)
		}
		if err := netlink.LinkSetUp(dummy); err != nil {
			return fmt.Errorf("set link up: %w", err)
		}
		addr, err := netlink.ParseAddr(ifaceAddr)
		if err != nil {
			return fmt.Errorf("parse addr: %w", err)
		}
		if err := netlink.AddrAdd(dummy, addr); err != nil {
			return fmt.Errorf("add addr: %w", err)
		}
		_, sidDst, err := net.ParseCIDR(sidRoute)
		if err != nil {
			return fmt.Errorf("parse SID route: %w", err)
		}
		route := &netlink.Route{LinkIndex: dummy.Attrs().Index, Dst: sidDst, Gw: net.ParseIP(sidGw)}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("add route to SID: %w", err)
		}
		return RouteEgressAdd(dst, net.ParseIP(sid), table)
	})
	if err != nil {
		t.Fatalf("setup (install route to delete): %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		return RouteEgressDel(dst, table)
	})
	if err != nil {
		t.Fatalf("RouteEgressDel: %v, want success", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, r := range routes {
			if r.Dst != nil && r.Dst.String() == dst.String() {
				return fmt.Errorf("route to %s still present in table %d after RouteEgressDel", dst, table)
			}
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}
