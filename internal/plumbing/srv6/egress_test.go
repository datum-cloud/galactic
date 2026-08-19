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

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// testCaseIPv6Zero names the shared "IPv6 zero" test-table-case fixture
// used across RouteEgressAdd/RouteMainAdd/EgressDefaultRouteAdd's own
// unspecified-gateway/SID rejection tests (goconst).
const testCaseIPv6Zero = "IPv6 zero"

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create a test network namespace and install routes; re-run via sudo")
	}
}

// setUpTestPinDir loads the real usid.c program (attach.Load, the same
// production loader every other integration test in this codebase that
// needs a real pinned map uses -- e.g. usidmap's own
// TestOpenPinnedRegistry_RoundTrip) into a fresh, throwaway bpffs
// directory, points this package's own pinDir seam at it for the
// duration of the calling test, and registers cleanup for both. Returns
// the directory so the calling test can also open its own independent
// second handle (egressroutemap.OpenPinnedEgressRouteTable) to verify
// what RouteEgressAdd/EgressDefaultRouteAdd actually installed.
func setUpTestPinDir(t *testing.T) string {
	t.Helper()

	testPinDir := fmt.Sprintf("/sys/fs/bpf/galactic-srv6-egress-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(testPinDir) })

	objs, err := attach.Load(testPinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() {
		if err := objs.Close(); err != nil {
			t.Errorf("close loader-side objects: %v", err)
		}
	})

	prevPinDir := pinDir
	pinDir = testPinDir
	t.Cleanup(func() { pinDir = prevPinDir })

	return testPinDir
}

// setUpResolvableSID creates a fresh test netns with a dummy interface
// (ifaceName/ifaceAddr) that has an on-link route to sid and a static,
// already-resolved neighbor entry for it -- everything
// egressroutemap.EgressRouteTable.Register's own resolveLinkAndL2 needs
// to succeed (a route via netlink.RouteGet, then a matching neighbor
// cache entry with a real hardware address), the same two-part
// requirement srv6.RouteEgressAdd's own pre-TC-BPF resolveNextHop had
// for exactly the same reason (see that function's own doc comment).
// Returns the netns so callers can run RouteEgressAdd/EgressDefaultRouteAdd
// inside it via nsObj.Do.
func setUpResolvableSID(t *testing.T, ifaceName, ifaceAddr, sid string) ns.NetNS {
	t.Helper()

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

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
		_, sidDst, err := net.ParseCIDR(sid + "/128")
		if err != nil {
			return fmt.Errorf("parse sid %q: %w", sid, err)
		}
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: dummy.Attrs().Index, Dst: sidDst}); err != nil {
			return fmt.Errorf("add on-link route for sid %q: %w", sid, err)
		}
		neigh := &netlink.Neigh{
			LinkIndex:    dummy.Attrs().Index,
			Family:       netlink.FAMILY_V6,
			State:        netlink.NUD_PERMANENT,
			IP:           net.ParseIP(sid),
			HardwareAddr: net.HardwareAddr{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
		}
		if err := netlink.NeighAdd(neigh); err != nil {
			return fmt.Errorf("add static neighbor entry for sid %q: %w", sid, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setUpResolvableSID: %v", err)
	}
	return nsObj
}

// TestRouteEgressAddRejectsUnspecifiedGateway verifies that RouteEgressAdd
// refuses to install an egress_route_table entry when it isn't handed a
// real SRv6 SID. This is the defense-in-depth backstop for the bug where a
// missing/zero SID upstream (e.g. an EVPN path with no Prefix-SID
// attribute) got fed straight through and silently installed a route
// encapsulating to "::ffff:0.0.0.0" — a route to nowhere — instead of
// failing loudly. The check runs before this function ever opens a pinned
// map, so this test needs no privileges and no real bpffs mount.
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

// TestRouteEgressAdd_InstallsForBothPrefixFamilies covers the TC-BPF
// replacement's own analog of what used to be a netlink Via-vs-Gw
// distinction: an IPv4 VPC prefix and an IPv6 VPC prefix must both
// install correctly into egress_route_table, landing in the right LPM
// slot (egress_route_key's own family field, not a route attribute
// choice) so usid_egress's dual-stack match (usid.c) finds each one for
// its own inner packet's address family and not the other's.
//
// Loads the real usid.c program (attach.Load, the real production
// loader) into a throwaway pin directory -- the same integration pattern
// usidmap's own TestOpenPinnedRegistry_RoundTrip already establishes --
// points this package's own pinDir seam at it, calls RouteEgressAdd, and
// reads the installed entry back through a second, independent handle
// (egressroutemap.OpenPinnedEgressRouteTable) to prove cross-process
// visibility, the whole point of pinning.
func TestRouteEgressAdd_InstallsForBothPrefixFamilies(t *testing.T) {
	requireRoot(t)
	testPinDir := setUpTestPinDir(t)

	const (
		ifaceName = "srv6egtest0"
		ifaceAddr = "2001:db8:1::1/64"
		sid       = "2001:db8:9::9"
		table     = 100
	)

	nsObj := setUpResolvableSID(t, ifaceName, ifaceAddr, sid)

	// Family/address-byte-layout correctness within the key itself is
	// covered by egressroutemap's own
	// TestEgressRouteTable_IPv4PrefixStoresAddressLeftJustified and
	// TestEgressRouteTable_SameTableIDDifferentFamilyDoNotCollide; this
	// test's own job is proving RouteEgressAdd actually reaches a real,
	// cross-process-visible pinned map entry at all, for both families.
	tests := []struct {
		name   string
		prefix string
	}{
		{name: "IPv4 VPC prefix", prefix: "172.20.20.2/32"},
		{name: "IPv6 VPC prefix", prefix: "fd20:10:ff02::/96"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, prefix, err := net.ParseCIDR(tt.prefix)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", tt.prefix, err)
			}

			err = nsObj.Do(func(_ ns.NetNS) error {
				return RouteEgressAdd(prefix, net.ParseIP(sid), table)
			})
			if err != nil {
				t.Fatalf("RouteEgressAdd(%s) = %v, want success", tt.prefix, err)
			}

			entryTable, closer, err := egressroutemap.OpenPinnedEgressRouteTable(testPinDir)
			if err != nil {
				t.Fatalf("open pinned egress_route_table: %v", err)
			}
			defer func() { _ = closer.Close() }()

			gotSID, ok, err := entryTable.Lookup(table, prefix)
			if err != nil {
				t.Fatalf("lookup installed entry: %v", err)
			}
			if !ok {
				t.Fatalf("installed entry not found for %s", tt.prefix)
			}
			if !gotSID.Equal(net.ParseIP(sid)) {
				t.Errorf("installed sid = %s, want %s", gotSID, sid)
			}
		})
	}
}

// TestRouteEgressDel_RemovesInstalledEntry covers RouteEgressAdd's
// counterpart: an installed entry must actually disappear from
// egress_route_table, not merely stop being returned by some
// higher-level cache.
func TestRouteEgressDel_RemovesInstalledEntry(t *testing.T) {
	requireRoot(t)
	testPinDir := setUpTestPinDir(t)

	const (
		ifaceName = "srv6egtest1"
		ifaceAddr = "2001:db8:2::1/64"
		sid       = "2001:db8:9::9"
		table     = 101
	)
	_, prefix, err := net.ParseCIDR("fd20:10:ff03::/96")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	nsObj := setUpResolvableSID(t, ifaceName, ifaceAddr, sid)

	err = nsObj.Do(func(_ ns.NetNS) error {
		return RouteEgressAdd(prefix, net.ParseIP(sid), table)
	})
	if err != nil {
		t.Fatalf("RouteEgressAdd: %v", err)
	}
	if err := RouteEgressDel(prefix, table); err != nil {
		t.Fatalf("RouteEgressDel: %v", err)
	}

	entryTable, closer, err := egressroutemap.OpenPinnedEgressRouteTable(testPinDir)
	if err != nil {
		t.Fatalf("open pinned egress_route_table: %v", err)
	}
	defer func() { _ = closer.Close() }()

	if _, ok, err := entryTable.Lookup(table, prefix); err != nil {
		t.Fatalf("lookup after delete: %v", err)
	} else if ok {
		t.Error("entry still present after RouteEgressDel")
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

// TestEgressDefaultRouteAdd_InstallsDefaultEntryForFirstShard proves
// EgressDefaultRouteAdd installs egress_route_table's ::/0 entry
// encapsulating toward the first configured shard SID, and that
// EgressDefaultRouteDel removes it cleanly -- the mechanism that finally
// gives a tenant VRF somewhere to send a packet with no more specific
// route, closing the gap nat66.c's own shard-receive side was always
// able to answer but nothing ever fed traffic into.
//
// Unlike this function's pre-TC-BPF implementation, no live route to
// each shard SID needs to exist first: usid_egress's own bpf_fib_lookup
// resolves the chosen SID fresh, per packet, so EgressDefaultRouteAdd
// itself no longer needs to (and no longer can, having no netlink
// dependency left at all) verify reachability at install time -- see
// this function's own doc comment for the "skip unresolvable shards"
// behavior this replaces and why it's no longer needed.
func TestEgressDefaultRouteAdd_InstallsDefaultEntryForFirstShard(t *testing.T) {
	requireRoot(t)
	testPinDir := setUpTestPinDir(t)

	const (
		ifaceName = "srv6egtest2"
		ifaceAddr = "2001:db8:4::1/64"
		shardSID1 = "2001:db8:ff01:1:e001::"
		shardSID2 = "2001:db8:ff03:1:e001::"
		table     = 42
	)
	nsObj := setUpResolvableSID(t, ifaceName, ifaceAddr, shardSID1)
	// shardSID2 is deliberately left unresolvable (no route/neighbor for
	// it at all): this test's own job is proving the first *resolvable*
	// shard wins, not that every configured shard must resolve.
	shardSIDs := []net.IP{net.ParseIP(shardSID1), net.ParseIP(shardSID2)}

	err := nsObj.Do(func(_ ns.NetNS) error {
		return EgressDefaultRouteAdd(table, shardSIDs)
	})
	if err != nil {
		t.Fatalf("EgressDefaultRouteAdd(%v) = %v, want success", shardSIDs, err)
	}

	entryTable, closer, err := egressroutemap.OpenPinnedEgressRouteTable(testPinDir)
	if err != nil {
		t.Fatalf("open pinned egress_route_table: %v", err)
	}
	defer func() { _ = closer.Close() }()

	gotSID, ok, err := entryTable.Lookup(table, egressroutemap.DefaultPrefix)
	if err != nil {
		t.Fatalf("lookup default entry: %v", err)
	}
	if !ok {
		t.Fatal("no default entry installed")
	}
	if !gotSID.Equal(net.ParseIP(shardSID1)) {
		t.Errorf("installed default entry sid = %s, want %s (the first configured shard)", gotSID, shardSID1)
	}

	if err := EgressDefaultRouteDel(table); err != nil {
		t.Fatalf("EgressDefaultRouteDel(%d) = %v, want success", table, err)
	}
	if _, ok, err := entryTable.Lookup(table, egressroutemap.DefaultPrefix); err != nil {
		t.Fatalf("lookup after delete: %v", err)
	} else if ok {
		t.Error("default entry still present after EgressDefaultRouteDel")
	}
}

// TestResolveNodeSourceAddress_ReturnsInterfaceAddress proves
// ResolveNodeSourceAddress finds the primary global IPv6 address on
// whichever interface attach.ResolveInterfaces names -- exactly the
// address the kernel's own source-address-selection rules (RTA_PREFSRC)
// picked automatically for the SEG6 lwtunnel mechanism this replaces (see
// this function's own doc comment).
//
// Uses config.EnvCNIEBPFInterfaces to pin attach.ResolveInterfaces at a
// specific interface, rather than relying on a real default route --
// found live in containerlab that guessing from the main-table default
// route (an earlier version of this function's own approach) picks the
// wrong interface entirely whenever the default route belongs to the
// container/pod network rather than the SRv6 underlay (eth0 vs eth1 in
// that lab's own topology), which is exactly the scenario this test's
// own setup reproduces: ifaceName here deliberately has no default route
// through it at all.
func TestResolveNodeSourceAddress_ReturnsInterfaceAddress(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName = "srv6srctest0"
		ifaceAddr = "2001:db8:7::2/64"
	)

	t.Setenv(config.EnvCNIEBPFInterfaces, ifaceName)

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
		// Deliberately no default route added through this interface --
		// see this test's own doc comment.
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	var got net.IP
	err = nsObj.Do(func(_ ns.NetNS) error {
		var doErr error
		got, doErr = ResolveNodeSourceAddress()
		return doErr
	})
	if err != nil {
		t.Fatalf("ResolveNodeSourceAddress: %v", err)
	}

	want := net.ParseIP("2001:db8:7::2")
	if !got.Equal(want) {
		t.Errorf("ResolveNodeSourceAddress() = %s, want %s", got, want)
	}
}

// TestResolveNodeSourceAddress_UnresolvableInterfaceFailsLoudly covers
// attach.ResolveInterfaces itself failing (e.g. the configured interface
// doesn't exist, or -- with no override set -- no default IPv6 route
// exists yet to auto-detect from, such as before the underlay eBGP
// session has converged) -- must fail with an actionable error, not
// silently return an unspecified/nil address that node_src_addr_table's
// own "all-zero means not configured" convention would otherwise treat
// as a legitimate value.
func TestResolveNodeSourceAddress_UnresolvableInterfaceFailsLoudly(t *testing.T) {
	requireRoot(t)

	t.Setenv(config.EnvCNIEBPFInterfaces, "srv6srctest-does-not-exist")

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		_, doErr := ResolveNodeSourceAddress()
		return doErr
	})
	if err == nil {
		t.Error("ResolveNodeSourceAddress() = nil error for a nonexistent interface, want an error")
	}
}

// TestResolvePublicUplink_ReturnsInterfaceIndexAndNeighborMAC covers the
// happy path: given a resolvable fabric-uplink interface with exactly one
// resolved IPv6 neighbor (this codebase's own topology never has more
// than one on a point-to-point uplink -- see ResolvePublicUplink's own
// doc comment), it must return that interface's own index, the
// neighbor's MAC as dmac, and the interface's own MAC as smac.
func TestResolvePublicUplink_ReturnsInterfaceIndexAndNeighborMAC(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName = "srv6puptest0"
		ifaceAddr = "2001:db8:8::2/64"
		neighAddr = "2001:db8:8::1"
	)
	neighMAC := net.HardwareAddr{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}

	t.Setenv(config.EnvCNIEBPFInterfaces, ifaceName)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	var wantIndex int
	var wantSmac net.HardwareAddr
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
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return fmt.Errorf("look up link: %w", err)
		}
		wantIndex = link.Attrs().Index
		wantSmac = link.Attrs().HardwareAddr
		return netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:    wantIndex,
			Family:       netlink.FAMILY_V6,
			State:        netlink.NUD_PERMANENT,
			IP:           net.ParseIP(neighAddr),
			HardwareAddr: neighMAC,
		})
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	var gotIndex int
	var gotDmac, gotSmac net.HardwareAddr
	err = nsObj.Do(func(_ ns.NetNS) error {
		var doErr error
		gotIndex, gotDmac, gotSmac, doErr = ResolvePublicUplink()
		return doErr
	})
	if err != nil {
		t.Fatalf("ResolvePublicUplink: %v", err)
	}

	if gotIndex != wantIndex {
		t.Errorf("ResolvePublicUplink() linkIndex = %d, want %d", gotIndex, wantIndex)
	}
	if gotDmac.String() != neighMAC.String() {
		t.Errorf("ResolvePublicUplink() dmac = %s, want %s (the resolved neighbor's own MAC)", gotDmac, neighMAC)
	}
	if gotSmac.String() != wantSmac.String() {
		t.Errorf("ResolvePublicUplink() smac = %s, want %s (the interface's own MAC)", gotSmac, wantSmac)
	}
}

// TestResolvePublicUplink_NoResolvedNeighborFailsLoudly covers the
// underlay-not-converged-yet case: the interface exists and is
// resolvable, but has no neighbor entry with a resolved link-layer
// address yet (e.g. this node just booted, before the underlay's own
// neighbor discovery has completed) -- must fail with an actionable
// error, not silently return a zero linkIndex/nil dmac/smac that
// public_uplink_table's own "link_ifindex == 0 means not configured"
// convention would otherwise treat as ambiguous with a genuine miss.
func TestResolvePublicUplink_NoResolvedNeighborFailsLoudly(t *testing.T) {
	requireRoot(t)

	const (
		ifaceName = "srv6puptest1"
		ifaceAddr = "2001:db8:9::2/64"
	)

	t.Setenv(config.EnvCNIEBPFInterfaces, ifaceName)

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
		// Deliberately no neighbor added -- see this test's own doc comment.
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		_, _, _, doErr := ResolvePublicUplink()
		return doErr
	})
	if err == nil {
		t.Error("ResolvePublicUplink() = nil error with no resolved neighbor, want an error")
	}
}
