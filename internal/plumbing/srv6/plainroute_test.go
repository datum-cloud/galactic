// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	plainTestIface   = "srv6ptest0"
	plainTestAddr    = "2001:db8:3::1/64"
	plainTestNextHop = "2001:db8:3::2"
	plainTestAltHop  = "2001:db8:3::3"
	plainTestGateway = "2001:db8:9::9" // a BGP next hop: reached through its own route
	plainTestPrefix  = "2001:db8:6060::/64"
)

// plainTestNetNS returns a fresh netns holding plainTestIface, addressed with
// plainTestAddr, and a main-table route to plainTestGateway via
// plainTestNextHop: the shape of an underlay route to a remote node's
// loopback.
func plainTestNetNS(t *testing.T) ns.NetNS {
	t.Helper()
	requireRoot(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	err = nsObj.Do(func(_ ns.NetNS) error {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: plainTestIface}}
		if err := netlink.LinkAdd(dummy); err != nil {
			return fmt.Errorf("add dummy link: %w", err)
		}
		if err := netlink.LinkSetUp(dummy); err != nil {
			return fmt.Errorf("set link up: %w", err)
		}
		addr, err := netlink.ParseAddr(plainTestAddr)
		if err != nil {
			return fmt.Errorf("parse addr: %w", err)
		}
		if err := netlink.AddrAdd(dummy, addr); err != nil {
			return fmt.Errorf("add addr: %w", err)
		}
		return setGatewayRoute(plainTestNextHop)
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	return nsObj
}

// setGatewayRoute points the main-table route to plainTestGateway at nextHop,
// as an underlay reconvergence would.
func setGatewayRoute(nextHop string) error {
	link, err := netlink.LinkByName(plainTestIface)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       mustCIDR(plainTestGateway + "/128"),
		Gw:        net.ParseIP(nextHop),
	})
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// onlyPlainRoute returns the single route in PlainRouteTable for prefix.
func onlyPlainRoute(prefix *net.IPNet) (*netlink.Route, error) {
	routes, err := plainRoutesFor(prefix)
	if err != nil {
		return nil, err
	}
	if len(routes) != 1 {
		return nil, fmt.Errorf("found %d plain routes for %s, want 1", len(routes), prefix)
	}
	return &routes[0], nil
}

func TestPlainRouteReplaceRejectsUnspecifiedGateway(t *testing.T) {
	prefix := mustCIDR(plainTestPrefix)
	tests := []struct {
		name    string
		gateway net.IP
	}{
		{name: "nil gateway", gateway: nil},
		{name: "IPv4 zero", gateway: net.IPv4zero},
		{name: testCaseIPv6Zero, gateway: net.IPv6unspecified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PlainRouteReplace(prefix, tt.gateway); err == nil {
				t.Errorf("PlainRouteReplace(%v) = nil error, want an error rejecting the unusable gateway", tt.gateway)
			}
		})
	}
}

// TestPlainRouteReplace_InstallsOwnedRouteResolvingIndirectGateway installs a
// plain route toward a gateway that is not on-link, and checks it lands in
// PlainRouteTable with PlainRouteProtocol, the resolved next hop and no
// encapsulation, never in the main table. Also covers PlainRouteList and
// PlainRouteDel.
func TestPlainRouteReplace_InstallsOwnedRouteResolvingIndirectGateway(t *testing.T) {
	nsObj := plainTestNetNS(t)
	prefix := mustCIDR(plainTestPrefix)

	err := nsObj.Do(func(_ ns.NetNS) error {
		changed, err := PlainRouteReplace(prefix, net.ParseIP(plainTestGateway))
		if err != nil {
			return fmt.Errorf("PlainRouteReplace: %w", err)
		}
		if !changed {
			return errors.New("PlainRouteReplace changed = false on first install, want true")
		}

		r, err := onlyPlainRoute(prefix)
		if err != nil {
			return err
		}
		if r.Protocol != PlainRouteProtocol {
			return fmt.Errorf("protocol = %d, want %d", r.Protocol, PlainRouteProtocol)
		}
		if r.Encap != nil {
			return fmt.Errorf("encap = %+v, want none", r.Encap)
		}
		if !r.Gw.Equal(net.ParseIP(plainTestNextHop)) {
			return fmt.Errorf("gw = %v, want the resolved next hop %s", r.Gw, plainTestNextHop)
		}

		main, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
			&netlink.Route{Table: unix.RT_TABLE_MAIN, Dst: prefix},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
		if err != nil {
			return err
		}
		if len(main) != 0 {
			return fmt.Errorf("main table holds %v, want no route for %s there", main, prefix)
		}

		owned, err := PlainRouteList()
		if err != nil {
			return err
		}
		if len(owned) != 1 || owned[0].String() != prefix.String() {
			return fmt.Errorf("PlainRouteList = %v, want [%s]", owned, prefix)
		}

		if err := PlainRouteDel(prefix); err != nil {
			return fmt.Errorf("PlainRouteDel: %w", err)
		}
		if err := PlainRouteDel(prefix); err != nil {
			return fmt.Errorf("PlainRouteDel of a missing route: %w", err)
		}
		owned, err = PlainRouteList()
		if err != nil {
			return err
		}
		if len(owned) != 0 {
			return fmt.Errorf("PlainRouteList after delete = %v, want none", owned)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPlainRouteReplace_FollowsUnderlayNextHop is the regression test for a
// plain route keeping the next hop it was first written with after the
// underlay route to its gateway moves.
func TestPlainRouteReplace_FollowsUnderlayNextHop(t *testing.T) {
	nsObj := plainTestNetNS(t)
	prefix := mustCIDR(plainTestPrefix)
	gw := net.ParseIP(plainTestGateway)

	err := nsObj.Do(func(_ ns.NetNS) error {
		if _, err := PlainRouteReplace(prefix, gw); err != nil {
			return fmt.Errorf("first PlainRouteReplace: %w", err)
		}
		changed, err := PlainRouteReplace(prefix, gw)
		if err != nil {
			return fmt.Errorf("repeat PlainRouteReplace: %w", err)
		}
		if changed {
			return errors.New("repeat PlainRouteReplace changed = true with nothing moved, want false")
		}

		if err := setGatewayRoute(plainTestAltHop); err != nil {
			return fmt.Errorf("move gateway route: %w", err)
		}
		changed, err = PlainRouteReplace(prefix, gw)
		if err != nil {
			return fmt.Errorf("PlainRouteReplace after move: %w", err)
		}
		if !changed {
			return errors.New("PlainRouteReplace changed = false after the underlay moved, want true")
		}
		r, err := onlyPlainRoute(prefix)
		if err != nil {
			return err
		}
		if !r.Gw.Equal(net.ParseIP(plainTestAltHop)) {
			return fmt.Errorf("gw = %v after the underlay moved, want %s", r.Gw, plainTestAltHop)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPlainRouteRules_UnderlayRouteTakesPrecedence checks the policy rules
// send traffic through a plain route only when the main table has nothing
// more specific than its default route, and through the underlay's route
// whenever it has one.
func TestPlainRouteRules_UnderlayRouteTakesPrecedence(t *testing.T) {
	nsObj := plainTestNetNS(t)
	prefix := mustCIDR(plainTestPrefix)
	dst := net.ParseIP("2001:db8:6060::1")

	err := nsObj.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(plainTestIface)
		if err != nil {
			return err
		}
		// A default route, as every real node has, must not shadow the plain
		// route.
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       mustCIDR("::/0"),
			Gw:        net.ParseIP("2001:db8:3::4"),
		}); err != nil {
			return fmt.Errorf("add default route: %w", err)
		}

		if err := EnsurePlainRouteRules(); err != nil {
			return fmt.Errorf("EnsurePlainRouteRules: %w", err)
		}
		if err := EnsurePlainRouteRules(); err != nil {
			return fmt.Errorf("EnsurePlainRouteRules again: %w", err)
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			rules, err := netlink.RuleList(family)
			if err != nil {
				return err
			}
			var suppress, lookup int
			for _, r := range rules {
				switch r.Priority {
				case PlainRouteSuppressRulePriority:
					suppress++
				case PlainRouteLookupRulePriority:
					lookup++
				}
			}
			if suppress != 1 || lookup != 1 {
				return fmt.Errorf("%s rules: %d suppress, %d lookup after two calls, want 1 each",
					familyName(family), suppress, lookup)
			}
		}

		if _, err := PlainRouteReplace(prefix, net.ParseIP(plainTestGateway)); err != nil {
			return fmt.Errorf("PlainRouteReplace: %w", err)
		}
		got, err := netlink.RouteGet(dst)
		if err != nil {
			return fmt.Errorf("RouteGet(%s): %w", dst, err)
		}
		gotTable := uint32(got[0].Table) //nolint:gosec // a kernel table ID is a uint32
		if gotTable != PlainRouteTable || !got[0].Gw.Equal(net.ParseIP(plainTestNextHop)) {
			return fmt.Errorf("with no underlay route, %s resolved via table %d gw %v, want table %d gw %s",
				dst, got[0].Table, got[0].Gw, PlainRouteTable, plainTestNextHop)
		}

		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       prefix,
			Gw:        net.ParseIP(plainTestAltHop),
			Protocol:  unix.RTPROT_BGP,
		}); err != nil {
			return fmt.Errorf("add underlay route: %w", err)
		}
		got, err = netlink.RouteGet(dst)
		if err != nil {
			return fmt.Errorf("RouteGet(%s): %w", dst, err)
		}
		if got[0].Table != unix.RT_TABLE_MAIN || !got[0].Gw.Equal(net.ParseIP(plainTestAltHop)) {
			return fmt.Errorf("with an underlay route, %s resolved via table %d gw %v, want main gw %s",
				dst, got[0].Table, got[0].Gw, plainTestAltHop)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPlainRouteReplace_RefusesGatewayBehindPlainRoute checks a plain route is
// never written toward a gateway reachable only through another plain route.
func TestPlainRouteReplace_RefusesGatewayBehindPlainRoute(t *testing.T) {
	nsObj := plainTestNetNS(t)

	err := nsObj.Do(func(_ ns.NetNS) error {
		if err := EnsurePlainRouteRules(); err != nil {
			return fmt.Errorf("EnsurePlainRouteRules: %w", err)
		}
		if _, err := PlainRouteReplace(mustCIDR("2001:db8:7000::/48"), net.ParseIP(plainTestGateway)); err != nil {
			return fmt.Errorf("install covering plain route: %w", err)
		}
		if _, err := PlainRouteReplace(mustCIDR(plainTestPrefix), net.ParseIP("2001:db8:7000::1")); err == nil {
			return errors.New("PlainRouteReplace via a gateway behind a plain route = nil error, want refusal")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRemoveLegacyPlainRoute checks only an unmarked main-table route, as an
// earlier galactic-router wrote, is removed, and an underlay route for the
// same kind of prefix is left alone.
func TestRemoveLegacyPlainRoute(t *testing.T) {
	nsObj := plainTestNetNS(t)
	legacy := mustCIDR("2001:db8:7070::/64")
	underlay := mustCIDR("2001:db8:7171::/64")

	err := nsObj.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(plainTestIface)
		if err != nil {
			return err
		}
		for _, r := range []*netlink.Route{
			{LinkIndex: link.Attrs().Index, Dst: legacy, Gw: net.ParseIP(plainTestNextHop)},
			{LinkIndex: link.Attrs().Index, Dst: underlay, Gw: net.ParseIP(plainTestNextHop), Protocol: unix.RTPROT_BGP},
		} {
			if err := netlink.RouteAdd(r); err != nil {
				return fmt.Errorf("add %s: %w", r.Dst, err)
			}
		}

		n, err := RemoveLegacyPlainRoute(legacy)
		if err != nil || n != 1 {
			return fmt.Errorf("RemoveLegacyPlainRoute(%s) = %d, %w, want 1, nil", legacy, n, err)
		}
		n, err = RemoveLegacyPlainRoute(underlay)
		if err != nil || n != 0 {
			return fmt.Errorf("RemoveLegacyPlainRoute(%s) = %d, %w, want 0, nil", underlay, n, err)
		}
		left, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
			&netlink.Route{Table: unix.RT_TABLE_MAIN, Dst: underlay},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
		if err != nil {
			return err
		}
		if len(left) != 1 {
			return fmt.Errorf("underlay route %s removed, want it kept", underlay)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
