// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Plain routes are the kernel routes installed for EVPN Type 5 paths carrying
// no route target: today the anycast ingress VIPs and each egress shard's SID
// /64 and masquerade address. Their next hop is an ordinary fabric address,
// so they need no encapsulation, but they cover destinations the underlay
// usually originates itself.
//
// They live in their own table, consulted only after the main table has had
// the chance to match with anything more specific than a default route. Two
// policy rules per family do that, ahead of the main table's own rule:
//
//	PlainRouteSuppressRulePriority: lookup main suppress_prefixlength 0
//	PlainRouteLookupRulePriority:   lookup PlainRouteTable
//
// The underlay's route, when there is one, therefore always wins, and a plain
// route only carries traffic the underlay has no specific route for.
//
// Keeping them out of the main table is the only way to defer to the
// underlay. FRR's zebra imports every main-table route it did not install as a
// "kernel" route with administrative distance 0, which beats any BGP route.
// A plain route there stops zebra installing the underlay's own route for the
// same prefix, whatever its metric, so a stale next hop is never corrected.
// zebra does not import a table it was not configured for, so it ignores this
// one.
const (
	// PlainRouteTable is the kernel routing table plain routes are installed
	// into. VRF tables are allocated upward from 1, and the sidecar return
	// tables start at 0xF000, so neither reaches it in practice.
	PlainRouteTable uint32 = 0xFFFE0000
	// PlainRouteProtocol marks every plain route as galactic-router's, so
	// `ip route show table all proto 250` lists exactly the routes it owns and
	// its garbage collection never touches anything else.
	PlainRouteProtocol netlink.RouteProtocol = 250
	// PlainRouteSuppressRulePriority is the priority of the rule letting the
	// main table match first with anything but its default route.
	PlainRouteSuppressRulePriority = 32000
	// PlainRouteLookupRulePriority is the priority of the rule consulting
	// PlainRouteTable. It must sit between PlainRouteSuppressRulePriority and
	// the main table's own rule at 32766, which still supplies the default
	// route.
	PlainRouteLookupRulePriority = 32001
)

// mainTable is RT_TABLE_MAIN, the table plain routes were installed into
// before they had their own.
const mainTable = unix.RT_TABLE_MAIN

// EnsurePlainRouteRules installs the two policy rules, for both IPv4 and IPv6,
// that consult PlainRouteTable after the main table's specific routes and
// before its default route. Idempotent: a rule already present is left alone.
func EnsurePlainRouteRules() error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		existing, err := netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("list %s policy rules: %w", familyName(family), err)
		}

		suppress := netlink.NewRule()
		suppress.Family = family
		suppress.Priority = PlainRouteSuppressRulePriority
		suppress.Table = mainTable
		suppress.SuppressPrefixlen = 0

		lookup := netlink.NewRule()
		lookup.Family = family
		lookup.Priority = PlainRouteLookupRulePriority
		lookup.Table = int(PlainRouteTable)

		for _, want := range []*netlink.Rule{suppress, lookup} {
			if ruleExists(existing, want) {
				continue
			}
			if err := netlink.RuleAdd(want); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("add %s policy rule %d lookup %d: %w",
					familyName(family), want.Priority, want.Table, err)
			}
		}
	}
	return nil
}

// ruleExists reports whether rules already holds one equivalent to want.
func ruleExists(rules []netlink.Rule, want *netlink.Rule) bool {
	for _, r := range rules {
		if r.Priority == want.Priority && r.Table == want.Table &&
			r.SuppressPrefixlen == want.SuppressPrefixlen {
			return true
		}
	}
	return false
}

// PlainRouteReplace installs or updates the plain route for prefix toward
// gateway in PlainRouteTable, and reports whether it changed anything.
//
// gateway is the path's BGP next hop: a fabric address, usually reached
// through a separate underlay route rather than on-link. The kernel does not
// resolve an IPv6 gateway recursively, so the route is written with the link
// and next hop the kernel would use for gateway right now. That choice goes
// stale when the underlay changes, so the caller must call this again
// whenever it might have; an unchanged route is left alone, so calling it
// often costs nothing.
//
// gateway must be a real address; an unspecified one would blackhole prefix.
// A gateway that resolves only through PlainRouteTable itself is refused, so
// plain routes never depend on each other.
func PlainRouteReplace(prefix *net.IPNet, gateway net.IP) (bool, error) {
	if prefix == nil {
		return false, errors.New("refusing to install plain route: prefix is nil")
	}
	if gateway == nil || gateway.IsUnspecified() {
		return false, fmt.Errorf("refusing to install route for %s: gateway %s is not a usable next-hop", prefix, gateway)
	}
	linkIndex, nextHop, table, err := resolveNextHop(gateway)
	if err != nil {
		return false, err
	}
	if table == PlainRouteTable {
		return false, fmt.Errorf("gateway %s for %s resolves only through another plain route", gateway, prefix)
	}

	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(PlainRouteTable),
		Protocol:  PlainRouteProtocol,
		LinkIndex: linkIndex,
	}
	if len(nextHop) == 0 {
		// gateway is on-link. A plain route still needs it stated explicitly,
		// or the kernel treats prefix itself as directly reachable here.
		nextHop = gateway
	}
	if prefix.IP.To4() != nil && nextHop.To4() == nil {
		route.Via = &netlink.Via{AddrFamily: netlink.FAMILY_V6, Addr: nextHop}
	} else {
		route.Gw = nextHop
	}

	existing, err := plainRoutesFor(prefix)
	if err != nil {
		return false, err
	}
	if len(existing) == 1 && sameForwarding(&existing[0], route) {
		return false, nil
	}
	if err := netlink.RouteReplace(route); err != nil {
		return false, fmt.Errorf("install plain route %s via %s: %w", prefix, nextHop, err)
	}
	return true, nil
}

// resolveNextHop flattens gateway into the link index plus the concrete
// next-hop address the kernel would forward through right now, via
// netlink.RouteGet, plus the table that lookup matched in. nextHop is nil
// when gateway is itself on-link.
//
// IPv6 route installation does not recurse through an indirect gateway:
// passing gateway as a route's Gw with no LinkIndex set fails with "no route
// to host" whenever gateway is reachable only via a separate route, such as
// through a link-local next-hop. BGP next-hops are usually exactly that
// shape.
func resolveNextHop(gateway net.IP) (linkIndex int, nextHop net.IP, table uint32, err error) {
	routes, err := netlink.RouteGet(gateway)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("no route to gateway %s: %w", gateway, err)
	}
	if len(routes) == 0 {
		return 0, nil, 0, fmt.Errorf("no route to gateway %s", gateway)
	}
	return routes[0].LinkIndex, routes[0].Gw, uint32(routes[0].Table), nil //nolint:gosec // a kernel table ID is a uint32
}

// sameForwarding reports whether existing already forwards the way desired
// would.
func sameForwarding(existing, desired *netlink.Route) bool {
	if existing.LinkIndex != desired.LinkIndex || existing.Protocol != desired.Protocol {
		return false
	}
	if !existing.Gw.Equal(desired.Gw) {
		return false
	}
	if existing.Via == nil || desired.Via == nil {
		return existing.Via == nil && desired.Via == nil
	}
	return existing.Via.Equal(desired.Via)
}

// plainRoutesFor returns the routes in PlainRouteTable for exactly prefix.
func plainRoutesFor(prefix *net.IPNet) ([]netlink.Route, error) {
	routes, err := netlink.RouteListFiltered(prefixFamily(prefix),
		&netlink.Route{Table: int(PlainRouteTable), Dst: prefix},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		return nil, fmt.Errorf("list plain routes for %s: %w", prefix, err)
	}
	return routes, nil
}

// PlainRouteDel removes the plain route for prefix from PlainRouteTable. A
// route that is already gone is not an error.
func PlainRouteDel(prefix *net.IPNet) error {
	err := netlink.RouteDel(&netlink.Route{
		Dst:      prefix,
		Table:    int(PlainRouteTable),
		Protocol: PlainRouteProtocol,
	})
	if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("delete plain route %s: %w", prefix, err)
	}
	return nil
}

// PlainRouteList returns the destination of every route in PlainRouteTable
// carrying PlainRouteProtocol, across both families.
func PlainRouteList() ([]*net.IPNet, error) {
	var dsts []*net.IPNet
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family,
			&netlink.Route{Table: int(PlainRouteTable), Protocol: PlainRouteProtocol},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			return nil, fmt.Errorf("list %s plain routes: %w", familyName(family), err)
		}
		for i := range routes {
			if routes[i].Dst != nil {
				dsts = append(dsts, routes[i].Dst)
			}
		}
	}
	return dsts, nil
}

// RemoveLegacyPlainRoute deletes the main-table route for exactly prefix that
// an earlier galactic-router left behind, reporting how many it removed.
//
// Those routes were written with no protocol, so the kernel recorded them as
// "boot", and they keep zebra from installing the underlay's route for the
// same prefix. Only an unencapsulated unicast "boot" route for prefix itself
// matches; a route FRR or the kernel installed carries its own protocol and is
// left alone.
func RemoveLegacyPlainRoute(prefix *net.IPNet) (int, error) {
	routes, err := netlink.RouteListFiltered(prefixFamily(prefix),
		&netlink.Route{Table: mainTable, Dst: prefix},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		return 0, fmt.Errorf("list main-table routes for %s: %w", prefix, err)
	}
	removed := 0
	for i := range routes {
		r := routes[i]
		if r.Protocol != unix.RTPROT_BOOT || r.Type != unix.RTN_UNICAST || r.Encap != nil {
			continue
		}
		if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
			return removed, fmt.Errorf("delete legacy main-table route %s: %w", prefix, err)
		}
		removed++
	}
	return removed, nil
}

func prefixFamily(prefix *net.IPNet) int {
	if prefix.IP.To4() != nil {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

func familyName(family int) string {
	if family == netlink.FAMILY_V4 {
		return "IPv4"
	}
	return "IPv6"
}
