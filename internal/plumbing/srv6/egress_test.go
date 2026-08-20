// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// testCaseIPv6Zero names the shared "IPv6 zero" test-table-case fixture
// used across RouteEgressAdd/RouteMainAdd/EgressDefaultRouteAdd's own
// unspecified-gateway/SID rejection tests (goconst).
const testCaseIPv6Zero = "IPv6 zero"

// defaultRoutePrefixString is the string form of defaultRoutePrefix
// (::/0), shared by every EgressDefaultRouteAdd/Del test below that needs
// to recognize the installed default route by its Dst field (goconst).
const defaultRoutePrefixString = "::/0"

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
		{name: testCaseIPv6Zero, gateway: net.IPv6unspecified},
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

// TestRouteMainAddRejectsUnspecifiedGateway mirrors
// TestRouteEgressAddRejectsUnspecifiedGateway for RouteMainAdd's identical
// guard.
func TestRouteMainAddRejectsUnspecifiedGateway(t *testing.T) {
	_, prefix, err := net.ParseCIDR("2001:db8:6060::1/128")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

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
			if err := RouteMainAdd(prefix, tt.gateway, 0); err == nil {
				t.Errorf("RouteMainAdd(%v) = nil error, want an error rejecting the unusable gateway", tt.gateway)
			}
		})
	}
}

// TestRouteMainAdd_InstallsPlainRouteNoEncap installs a RouteMainAdd route
// against a real kernel routing table and asserts it lands as a plain
// gateway route with no SEG6 (or any other) encapsulation attached --
// the entire point of RouteMainAdd over RouteEgressAdd (see its own doc
// comment). Also exercises RouteMainDel as the add/delete round trip.
func TestRouteMainAdd_InstallsPlainRouteNoEncap(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName = "srv6mtest0"
		ifaceAddr = "2001:db8:2::1/64"
		gateway   = "2001:db8:2::2" // on-link next-hop, no encap SID involved
		vipPrefix = "2001:db8:6060::1/128"
		table     = 0 // main table -- see matchTableID's own doc comment
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
		return netlink.AddrAdd(dummy, addr)
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, prefix, err := net.ParseCIDR(vipPrefix)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", vipPrefix, err)
	}
	gw := net.ParseIP(gateway)

	err = nsObj.Do(func(_ ns.NetNS) error {
		return RouteMainAdd(prefix, gw, table)
	})
	if err != nil {
		t.Fatalf("RouteMainAdd(%s) = %v, want success", vipPrefix, err)
	}

	var installed *netlink.Route
	err = nsObj.Do(func(_ ns.NetNS) error {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
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
	if installed.Encap != nil {
		t.Errorf("installed route for %s has Encap %+v, want no encapsulation at all", vipPrefix, installed.Encap)
	}
	if installed.Gw == nil || !installed.Gw.Equal(gw) {
		t.Errorf("installed route for %s has Gw %v, want %v", vipPrefix, installed.Gw, gw)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		return RouteMainDel(prefix, table)
	})
	if err != nil {
		t.Fatalf("RouteMainDel(%s) = %v, want success", vipPrefix, err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for i := range routes {
			if routes[i].Dst != nil && routes[i].Dst.String() == prefix.String() {
				return fmt.Errorf("route to %s still present in table %d after RouteMainDel", prefix, table)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify deleted route: %v", err)
	}
}

// TestRouteMainAdd_ResolvesIndirectGateway is the regression test for the
// bug found live in containerlab: RouteMainAdd originally passed gateway
// straight through as a route's plain Gw with no LinkIndex, which fails
// with "no route to host" whenever gateway is only reachable via its own
// separate route rather than being on-link itself -- exactly the shape of
// a real EVPN path's BGP next-hop (reached through a link-local next-hop,
// not directly on the receiving node's own subnet). RouteEgressAdd already
// handled this via netlink.RouteGet (see resolveNextHop); RouteMainAdd
// initially didn't. Mirrors TestRouteEgressAdd_InstallsForBothPrefixFamilies'
// own multi-hop setup.
func TestRouteMainAdd_ResolvesIndirectGateway(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName     = "srv6mtest1"
		ifaceAddr     = "2001:db8:3::1/64"
		gatewayRoute  = "2001:db8:9::9/128" // reachable via ifaceAddr's subnet
		onLinkNextHop = "2001:db8:3::2"     // on-link next-hop for gatewayRoute
		gateway       = "2001:db8:9::9"     // NOT on-link -- reached indirectly
		vipPrefix     = "2001:db8:6060::1/128"
		table         = 0
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
		_, gwDst, err := net.ParseCIDR(gatewayRoute)
		if err != nil {
			return fmt.Errorf("parse gateway route: %w", err)
		}
		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: dummy.Attrs().Index,
			Dst:       gwDst,
			Gw:        net.ParseIP(onLinkNextHop),
		})
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, prefix, err := net.ParseCIDR(vipPrefix)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", vipPrefix, err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		return RouteMainAdd(prefix, net.ParseIP(gateway), table)
	})
	if err != nil {
		t.Fatalf("RouteMainAdd(%s) via indirect gateway %s = %v, want success", vipPrefix, gateway, err)
	}
}

// TestEgressDefaultRouteAdd_EmptyShardListIsANoop covers the "no shard
// configured yet" case config.EnvCNINAT66ShardSIDs's own doc comment
// describes as normal, not an error -- no root needed since nothing ever
// reaches netlink.
func TestEgressDefaultRouteAdd_EmptyShardListIsANoop(t *testing.T) {
	if err := EgressDefaultRouteAdd(1, nil); err != nil {
		t.Errorf("EgressDefaultRouteAdd(nil) = %v, want nil for an empty shard list", err)
	}
	if err := EgressDefaultRouteAdd(1, []net.IP{}); err != nil {
		t.Errorf("EgressDefaultRouteAdd([]) = %v, want nil for an empty shard list", err)
	}
}

// TestEgressDefaultRouteAddRejectsUnspecifiedShardSID mirrors
// TestRouteEgressAddRejectsUnspecifiedGateway/TestRouteMainAddRejectsUnspecifiedGateway:
// a shard SID that is nil or the unspecified address would otherwise
// install a route to nowhere.
func TestEgressDefaultRouteAddRejectsUnspecifiedShardSID(t *testing.T) {
	tests := []struct {
		name string
		sids []net.IP
	}{
		{name: "nil shard SID", sids: []net.IP{nil}},
		{name: testCaseIPv6Zero, sids: []net.IP{net.IPv6unspecified}},
		{name: "one good, one unspecified", sids: []net.IP{net.ParseIP("2001:db8:ff01::1"), net.IPv6unspecified}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := EgressDefaultRouteAdd(1, tt.sids); err == nil {
				t.Errorf("EgressDefaultRouteAdd(%v) = nil error, want an error rejecting the unusable shard SID", tt.sids)
			}
		})
	}
}

// TestEgressDefaultRouteAdd_InstallsMultipathAcrossShards proves the
// installed ::/0 route fans out across every configured shard SID as a
// separate SEG6-encapsulating nexthop, and that EgressDefaultRouteDel
// removes it cleanly -- the mechanism that finally gives a tenant VRF
// somewhere to send a packet with no more specific route, closing the gap
// nat66.c's own shard-receive side was always able to answer but nothing
// ever fed traffic into (see this function's own doc comment).
func TestEgressDefaultRouteAdd_InstallsMultipathAcrossShards(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName = "srv6mtest2"
		ifaceAddr = "2001:db8:4::1/64"
		shardSID1 = "2001:db8:ff01:1:e001::"
		shardSID2 = "2001:db8:ff03:1:e001::"
		table     = 42
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
		// resolveNextHop (via netlink.RouteGet) needs a real route to each
		// shard SID before EgressDefaultRouteAdd can resolve it -- neither
		// SID is naturally on-link over ifaceAddr's own /64, so each gets
		// an explicit on-link /128 host route, mirroring how a real
		// fabric's own SRv6 locator routes would already exist by the
		// time this function ever runs (see RouteMainAdd's identical
		// ordering dependency on RouteMainAdd's own doc comment).
		for _, sid := range []string{shardSID1, shardSID2} {
			_, sidDst, err := net.ParseCIDR(sid + "/128")
			if err != nil {
				return fmt.Errorf("parse shard SID %q: %w", sid, err)
			}
			if err := netlink.RouteAdd(&netlink.Route{LinkIndex: dummy.Attrs().Index, Dst: sidDst}); err != nil {
				return fmt.Errorf("add on-link route for shard SID %q: %w", sid, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	shardSIDs := []net.IP{net.ParseIP(shardSID1), net.ParseIP(shardSID2)}

	err = nsObj.Do(func(_ ns.NetNS) error {
		return EgressDefaultRouteAdd(table, shardSIDs)
	})
	if err != nil {
		t.Fatalf("EgressDefaultRouteAdd(%v) = %v, want success", shardSIDs, err)
	}

	var installed *netlink.Route
	err = nsObj.Do(func(_ ns.NetNS) error {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for i := range routes {
			if routes[i].Dst != nil && routes[i].Dst.String() == defaultRoutePrefixString {
				installed = &routes[i]
				return nil
			}
		}
		return fmt.Errorf("no default route found in table %d", table)
	})
	if err != nil {
		t.Fatalf("verify installed route: %v", err)
	}
	if len(installed.MultiPath) != len(shardSIDs) {
		t.Fatalf("installed default route has %d nexthops, want %d", len(installed.MultiPath), len(shardSIDs))
	}

	// Per-nexthop RTA_ENCAP within RTA_MULTIPATH round-trips through the
	// kernel correctly (confirmed live against `ip -6 route show`) but the
	// vendored netlink library's own RouteListFiltered doesn't decode it
	// back into NexthopInfo.Encap -- every nexthop above reads back
	// Encap == nil regardless of what was actually installed. Shell out to
	// `ip -6 route` (real ground truth, the same tool this session's own
	// live containerlab diagnostics already trusted over library/tcpdump
	// artifacts) rather than asserting against a field this library can't
	// populate.
	var out []byte
	err = nsObj.Do(func(_ ns.NetNS) error {
		var cmdErr error
		out, cmdErr = exec.CommandContext(
			context.Background(), "ip", "-6", "route", "show", "table", strconv.Itoa(table),
		).CombinedOutput()
		return cmdErr
	})
	if err != nil {
		t.Fatalf("ip -6 route show table %d: %v (%s)", table, err, out)
	}
	for _, sid := range shardSIDs {
		want := "encap seg6 mode encap.red segs 1 [ " + sid.String() + " ]"
		if !strings.Contains(string(out), want) {
			t.Errorf("ip -6 route show table %d = %q, want a nexthop containing %q", table, out, want)
		}
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		return EgressDefaultRouteDel(table)
	})
	if err != nil {
		t.Fatalf("EgressDefaultRouteDel(%d) = %v, want success", table, err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for i := range routes {
			if routes[i].Dst != nil && routes[i].Dst.String() == defaultRoutePrefixString {
				return fmt.Errorf("default route still present in table %d after EgressDefaultRouteDel", table)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify deleted route: %v", err)
	}
}

// TestEgressDefaultRouteAdd_SkipsUnresolvableShardButSucceeds is the
// regression test for a real bug found live: a shard node can never
// resolve a route to its *own* advertised SID (GoBGP, like every BGP
// implementation, never reflects a self-originated path back into that
// same node's own received-path processing -- see this function's own
// doc comment), so any tenant node that is also a configured shard
// (this lab's own "reuse the site workers as shards" layout) always has
// exactly one permanently-unresolvable entry in shardSIDs. The original
// implementation aborted the entire multipath route on the first
// unresolvable nexthop, which meant *no default route at all* on every
// shard node -- confirmed live: dfw-worker's own tenant pods failed CNI
// ADD outright with "no route to gateway 2001:db8:ff01:1:e001:: (dfw's
// own shard SID): invalid argument" even though sjc's and iad's shard
// SIDs resolved fine from that same node. This test proves a mix of one
// resolvable and one unresolvable shard SID still installs a route (with
// only the resolvable one as a nexthop), not an error.
func TestEgressDefaultRouteAdd_SkipsUnresolvableShardButSucceeds(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName       = "srv6mtest3"
		ifaceAddr       = "2001:db8:5::1/64"
		resolvableSID   = "2001:db8:ff02:1:e001::"
		unresolvableSID = "2001:db8:ff01:1:e001::" // no route ever installed for this one
		table           = 43
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
		_, sidDst, err := net.ParseCIDR(resolvableSID + "/128")
		if err != nil {
			return fmt.Errorf("parse shard SID: %w", err)
		}
		return netlink.RouteAdd(&netlink.Route{LinkIndex: dummy.Attrs().Index, Dst: sidDst})
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	shardSIDs := []net.IP{net.ParseIP(unresolvableSID), net.ParseIP(resolvableSID)}

	err = nsObj.Do(func(_ ns.NetNS) error {
		return EgressDefaultRouteAdd(table, shardSIDs)
	})
	if err != nil {
		t.Fatalf("EgressDefaultRouteAdd(%v) = %v, want success with the resolvable shard used", shardSIDs, err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for i := range routes {
			if routes[i].Dst == nil || routes[i].Dst.String() == defaultRoutePrefixString {
				// The kernel/netlink read path collapses a single-nexthop
				// RTA_MULTIPATH route back into plain Gw/Encap fields, not
				// a one-element MultiPath slice (confirmed live against
				// `ip -6 route show`, which does report the SEG6 encap
				// correctly either way) -- count either shape as "one
				// nexthop", matching what this shard-count assertion
				// actually cares about.
				nexthops := len(routes[i].MultiPath)
				if nexthops == 0 && routes[i].Gw != nil && routes[i].Encap != nil {
					nexthops = 1
				}
				if nexthops != 1 {
					return fmt.Errorf("installed default route has %d nexthops, want exactly 1 (the resolvable shard)",
						nexthops)
				}
				return nil
			}
		}
		return fmt.Errorf("no default route found in table %d", table)
	})
	if err != nil {
		t.Fatalf("verify installed route: %v", err)
	}
}

// TestEgressDefaultRouteAdd_AllShardsUnresolvableFails is
// TestEgressDefaultRouteAdd_SkipsUnresolvableShardButSucceeds's negative
// counterpart: when *every* configured shard SID is unresolvable, there
// is nothing to install a route with at all, and this must fail loudly
// rather than silently install a route with zero nexthops.
func TestEgressDefaultRouteAdd_AllShardsUnresolvableFails(t *testing.T) {
	shardSIDs := []net.IP{net.ParseIP("2001:db8:ff01:1:e001::"), net.ParseIP("2001:db8:ff02:1:e001::")}
	if err := EgressDefaultRouteAdd(44, shardSIDs); err == nil {
		t.Errorf("EgressDefaultRouteAdd(%v) = nil error, want an error when no shard SID is resolvable", shardSIDs)
	}
}
