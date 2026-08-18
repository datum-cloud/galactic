// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// pinDir is the bpffs directory RouteEgressAdd/RouteEgressDel/
// EgressDefaultRouteAdd/EgressDefaultRouteDel open egress_route_table
// from -- a package var defaulting to attach.PinDir (the same seam
// internal/cnibgp/cnibgp.go's own ebpfPinDir var provides), overridable in
// this package's own tests so they don't depend on a real bpffs mount or
// root privileges the way a live pinned-map integration test would.
var pinDir = attach.PinDir

// RouteEgressAdd installs an egress_route_table entry for prefix in Linux
// VRF table tableID, encapsulating toward the given SRv6 SID (gateway) --
// the TC-BPF replacement for what used to be a kernel-native SEG6 encap
// route (netlink.SEG6Encap). See docs/plans/tc-bpf-egress-srv6-encap.md
// for why: that kernel mechanism is confirmed broken by CVE-2026-31668
// under this codebase's own per-tenant-VRF architecture (seg6 lwtunnel's
// dst_cache reused blindly across the input/output resolution paths'
// differing routing contexts), not fixable by any change to how this
// package calls it.
//
// gateway must be a real SRv6 SID: an unspecified address (0.0.0.0 or ::,
// including its IPv4-mapped ::ffff:0.0.0.0 form) means the caller never
// resolved a real destination SID — installing it anyway would silently
// blackhole traffic to prefix behind a route to nowhere, which is exactly
// what happened before this check existed (an EVPN path with no usable SID
// attribute was fed straight through). Fail loudly instead --
// egressroutemap.EgressRouteTable.Register itself already enforces this.
//
// Unlike the netlink-route mechanism this replaces, this function no
// longer resolves gateway's own link/next-hop at install time
// (resolveNextHop, below, is no longer called from here): usid_egress's
// own bpf_fib_lookup() resolves that fresh, per packet -- see
// egress_route_value's doc comment in usid.c for why that's both simpler
// and self-healing.
func RouteEgressAdd(prefix *net.IPNet, gateway net.IP, tableID uint32) error {
	// Checked here, before ever touching bpffs, not left solely to
	// egressroutemap.EgressRouteTable.Register's own identical guard: a
	// caller passing a bad gateway shouldn't need a real pinned map (or
	// root) on hand just to get the right error back -- matching this
	// function's own pre-TC-BPF behavior, which failed this same check
	// before its first netlink call.
	if gateway == nil || gateway.IsUnspecified() {
		return fmt.Errorf("refusing to install egress route for %s: gateway %s is not a usable SRv6 SID", prefix, gateway)
	}
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("srv6: RouteEgressAdd: %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use
	return table.Register(tableID, prefix, gateway)
}

// resolveNextHop resolves gateway's real, immediate next-hop -- the exact
// link plus (unless gateway is itself on-link) the concrete address the
// kernel would actually forward through right now -- via netlink.RouteGet.
//
// This flattening matters because IPv6 route installation does not recurse
// through an indirect gateway on its own: passing gateway straight through
// as a route's Gw with no LinkIndex set fails with "no route to host"
// whenever gateway is only reachable via its own separate route (e.g.
// through a link-local next-hop) rather than being on-link itself --
// confirmed empirically live in containerlab, where every BGP next-hop
// used as a plain gateway (RouteMainAdd, below) is exactly this indirect
// shape.
//
// Only RouteMainAdd calls this today: RouteEgressAdd/EgressDefaultRouteAdd
// used to (their own SEG6 encap routes needed the identical flattening),
// but no longer do -- usid_egress's own per-packet bpf_fib_lookup replaces
// that resolution entirely for both (see RouteEgressAdd's own doc comment).
func resolveNextHop(gateway net.IP) (linkIndex int, nextHop net.IP, err error) {
	routes, err := netlink.RouteGet(gateway)
	if err != nil {
		return 0, nil, fmt.Errorf("no route to gateway %s: %w", gateway, err)
	}
	if len(routes) == 0 {
		return 0, nil, fmt.Errorf("no route to gateway %s", gateway)
	}
	return routes[0].LinkIndex, routes[0].Gw, nil
}

// RouteEgressDel removes the egress_route_table entry for prefix from
// Linux VRF table tableID -- RouteEgressAdd's counterpart.
func RouteEgressDel(prefix *net.IPNet, tableID uint32) error {
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("srv6: RouteEgressDel: %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use
	return table.Unregister(tableID, prefix)
}

// RouteMainAdd installs a plain route for prefix in routing table tableID,
// forwarding to gateway via ordinary recursive next-hop resolution -- no
// SEG6 encapsulation, unlike RouteEgressAdd, and untouched by the
// TC-BPF migration RouteEgressAdd/EgressDefaultRouteAdd underwent above:
// this function never called netlink.SEG6Encap in the first place, so it
// was never exposed to CVE-2026-31668 at all (see its own doc comment
// below for why an anycast route specifically must not be SEG6-wrapped).
//
// This exists for EVPN Type 5 paths that carry no Route Target extended
// community at all (see matchTableID in internal/runtime/gobgp/monitor.go):
// NetworkGatewayReconciler's anycast ingress-VIP advertisements are the one
// case today, deliberately left VRFID/Function-less because they name no
// tenant VRF (that reconciler's own package doc comment). Their EVPN path
// therefore carries no Prefix-SID either, so gateway here is always the
// path's plain BGP next-hop -- a real, already fabric-reachable node
// address (how else could this path's own BGP session exist), not a uSID
// decap SID. Wrapping the packet in another SEG6/IPv6-in-IPv6 header toward
// that address the way RouteEgressAdd does for a tenant VRF prefix would
// only make it undeliverable: nothing there is listening for that
// encapsulation the way usid_ingress listens for a real uSID SID's traffic.
// Ordinary recursive forwarding is what an anycast route actually needs.
//
// gateway must be a real address for the same reason RouteEgressAdd
// requires one: an unspecified gateway would silently blackhole prefix
// behind a route to nowhere.
func RouteMainAdd(prefix *net.IPNet, gateway net.IP, tableID uint32) error {
	if gateway == nil || gateway.IsUnspecified() {
		return fmt.Errorf("refusing to install route for %s: gateway %s is not a usable next-hop", prefix, gateway)
	}
	linkIndex, nextHop, err := resolveNextHop(gateway)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		Dst:       prefix,
		Table:     int(tableID),
		LinkIndex: linkIndex,
	}
	if len(nextHop) > 0 {
		if prefix.IP.To4() != nil {
			route.Via = &netlink.Via{AddrFamily: netlink.FAMILY_V6, Addr: nextHop}
		} else {
			route.Gw = nextHop
		}
	} else {
		// gateway itself is on-link (RouteGet found no further next-hop of
		// its own) -- unlike RouteEgressAdd's SEG6 encap case, where the
		// segment list alone already fully specifies the destination, a
		// plain route needs an explicit gateway here or the kernel would
		// treat prefix itself as directly reachable on this link.
		route.Gw = gateway
	}
	return netlink.RouteReplace(route)
}

// RouteMainDel removes the plain route for prefix from routing table
// tableID -- RouteMainAdd's counterpart, mirroring RouteEgressDel.
func RouteMainDel(prefix *net.IPNet, tableID uint32) error {
	return netlink.RouteDel(&netlink.Route{
		Dst:   prefix,
		Table: int(tableID),
	})
}

// EgressDefaultRouteAdd installs egress_route_table's default (::/0)
// entry for Linux VRF table tableID, encapsulating toward the first
// usable address in shardSIDs -- the TC-BPF replacement for what used to
// be a kernel-native SEG6 encap default route (see RouteEgressAdd's own
// doc comment for why). This is the missing half of the design plan's §3
// sharded NAT66 tier: nat66.c's own shard-receive side has always been
// able to decap and NAT a packet addressed to its own shard_sid, but
// nothing ever produced such a packet -- no code anywhere installed a
// default route in a tenant VRF at all, so a backend with no more
// specific destination simply had no route out (confirmed live: "no
// route to host" from vrf60's own table). This closes that gap the same
// way RouteEgressAdd closes it for a specific intra-VPC destination.
//
// Picking only the first usable shard, rather than spreading load across
// all of them, is a deliberate simplification: design plan §3.2's own
// per-flow hash (internal/maglev, or an earlier version of this
// function's own kernel-ECMP-multipath approximation of it) was never a
// hard requirement -- §3.5 treats shard-set-change disruption as a
// property to prove, not one gating this mechanism's existence at all --
// and correctness (a route exists, traffic flows) matters more here than
// shard load distribution. Revisit with a real selection mechanism (a
// second, larger LPM/hash map in usid.c, or per-flow hashing inside
// usid_egress itself) if per-shard load spreading is ever needed.
//
// shardSIDs must be non-empty -- EgressDefaultRouteAdd installs nothing
// and returns nil when it is, the same "nothing configured yet, not an
// error" stance GALACTIC_CNI_NAT66_SHARD_SIDS's own doc comment takes. An
// unspecified/nil entry is a real misconfiguration and fails loudly
// (matching RouteEgressAdd's own guard, enforced by
// egressroutemap.EgressRouteTable.Register).
//
// Unlike the netlink-route mechanism this replaces, EgressDefaultRouteAdd
// no longer needs to skip a shard SID it cannot yet resolve a route to
// (a real, previously-necessary case: a tenant node that is *also* one of
// the configured shards itself, this lab's own "reuse the site workers as
// shards" layout, can never resolve a route to its *own* advertised SID --
// GoBGP, like every BGP implementation, never reflects a self-originated
// path back into that same node's received-path processing). That
// resolvability check existed only because the old mechanism needed a
// concrete link/next-hop *at install time* (resolveNextHop); this one
// doesn't -- usid_egress's own bpf_fib_lookup resolves the chosen SID
// fresh, per packet, so an unreachable shard now simply fails that
// per-packet lookup (DROP_REASON_EGRESS_ROUTE_FIB_LOOKUP_FAILED) instead
// of ever needing to be detected here.
func EgressDefaultRouteAdd(tableID uint32, shardSIDs []net.IP) error {
	if len(shardSIDs) == 0 {
		return nil
	}
	// Checked here, before ever touching bpffs -- see RouteEgressAdd's
	// identical guard for why.
	if sid := shardSIDs[0]; sid == nil || sid.IsUnspecified() {
		return fmt.Errorf("refusing to install NAT66 default route: shard SID %s is not a usable SRv6 SID", sid)
	}
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("srv6: EgressDefaultRouteAdd: %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use
	return table.Register(tableID, egressroutemap.DefaultPrefix, shardSIDs[0])
}

// EgressDefaultRouteDel removes egress_route_table's default (::/0) entry
// for Linux VRF table tableID -- EgressDefaultRouteAdd's counterpart.
func EgressDefaultRouteDel(tableID uint32) error {
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("srv6: EgressDefaultRouteDel: %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use
	return table.Unregister(tableID, egressroutemap.DefaultPrefix)
}

// ResolveNodeSourceAddress resolves this node's own SRv6/underlay-facing
// source address: the primary global IPv6 address on whichever interface
// currently carries the kernel's own main-table IPv6 default route.
//
// This is the address usid_egress's egress-routing extension writes into
// every outer header it pushes (via egressroutemap.NodeSourceAddress) --
// the TC-BPF replacement's own analog of a property the kernel-native
// SEG6 lwtunnel mechanism gave for free, via ordinary IPv6
// source-address-selection: confirmed live, `ip -6 route get <SID>`
// reported `src 2001:db8:1:10::2` (this node's own fabric-facing
// address) for every SEG6-encapsulated route this package ever installed,
// with no explicit `src` ever configured anywhere in this codebase.
// Deriving it the same way here -- from the node's own live routing
// state, not a new piece of required operator configuration -- keeps
// that same "just works, no new config" property for the TC-BPF
// mechanism, at the one-time cost of running this resolution once at
// datapath registration rather than getting it for free per-route.
func ResolveNodeSourceAddress() (net.IP, error) {
	defaultDst := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Dst: defaultDst, Table: unix.RT_TABLE_MAIN},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list main-table IPv6 default route: %w", err)
	}
	if len(routes) == 0 {
		return nil, errors.New("no main-table IPv6 default route found -- can't determine this node's own source address")
	}

	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("resolve default route's own link (ifindex %d): %w", routes[0].LinkIndex, err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("list addresses on %s: %w", link.Attrs().Name, err)
	}
	for _, a := range addrs {
		if a.Scope == unix.RT_SCOPE_UNIVERSE && !a.IP.IsUnspecified() {
			return a.IP, nil
		}
	}
	return nil, fmt.Errorf("no global-scope IPv6 address found on %s (default-route interface)", link.Attrs().Name)
}
