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

// pinDir is the bpffs directory the egress route helpers open
// egress_route_table from. A package var so tests can redirect it and avoid
// needing a real bpffs mount or root.
var pinDir = attach.PinDir

// RouteEgressAdd installs an egress_route_table entry for prefix in Linux VRF
// table tableID, so usid_egress encapsulates matching traffic toward the SRv6
// SID gateway. It replaces a kernel SEG6 encap route, which is unusable here:
// the seg6 lwtunnel reuses one dst_cache across the input and output
// resolution paths, whose routing contexts differ once every tenant has its
// own VRF.
//
// gateway must be a real SRv6 SID. An unspecified address (:: or 0.0.0.0,
// including the IPv4-mapped form) means the caller never resolved a
// destination SID, and installing it would blackhole prefix behind a route to
// nowhere. Register resolves gateway's link and L2 addresses as part of the
// write, so an unreachable gateway also fails here rather than at packet
// time.
func RouteEgressAdd(prefix *net.IPNet, gateway net.IP, tableID uint32) error {
	// Checked before touching bpffs, duplicating Register's own guard, so a
	// caller passing a bad gateway gets the right error without needing a
	// pinned map or root.
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

// resolveNextHop flattens gateway into the link index plus the concrete
// next-hop address the kernel would forward through right now, via
// netlink.RouteGet. nextHop is nil when gateway is itself on-link.
//
// IPv6 route installation does not recurse through an indirect gateway:
// passing gateway as a route's Gw with no LinkIndex set fails with "no route
// to host" whenever gateway is reachable only via a separate route, such as
// through a link-local next-hop. BGP next-hops are usually exactly that
// shape.
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

// RouteEgressDel removes the egress_route_table entry for prefix from Linux
// VRF table tableID. The counterpart to RouteEgressAdd.
func RouteEgressDel(prefix *net.IPNet, tableID uint32) error {
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("srv6: RouteEgressDel: %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use
	return table.Unregister(tableID, prefix)
}

// RouteMainAdd installs a plain kernel route for prefix in routing table
// tableID, forwarding to gateway through ordinary recursive next-hop
// resolution and no encapsulation at all.
//
// It exists for EVPN Type 5 paths carrying no Route Target extended community,
// which today means the anycast ingress-VIP advertisements that name no tenant
// VRF. Such a path carries no Prefix-SID either, so gateway is the path's
// plain BGP next-hop: a node address already reachable over the fabric, not a
// uSID decap SID. Wrapping it in an outer IPv6 header the way RouteEgressAdd
// does would make the packet undeliverable, because nothing at that address
// listens for that encapsulation.
//
// gateway must be a real address; an unspecified one would blackhole prefix.
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
		// gateway is on-link. A plain route still needs it stated explicitly,
		// or the kernel treats prefix itself as directly reachable here.
		route.Gw = gateway
	}
	return netlink.RouteReplace(route)
}

// RouteMainDel removes the plain route for prefix from routing table tableID.
// The counterpart to RouteMainAdd.
func RouteMainDel(prefix *net.IPNet, tableID uint32) error {
	return netlink.RouteDel(&netlink.Route{
		Dst:   prefix,
		Table: int(tableID),
	})
}

// EgressDefaultRouteAdd installs egress_route_table's default (::/0) entry for
// Linux VRF table tableID, encapsulating toward the first usable address in
// shardSIDs. It gives a tenant VRF a route out for any destination with no
// more specific entry, so traffic reaches the egress shard tier that decaps and
// translates it.
//
// See EgressPrefixRouteAdd, which this delegates to, for shard selection and
// error behavior.
func EgressDefaultRouteAdd(tableID uint32, shardSIDs []net.IP) error {
	return EgressPrefixRouteAdd(tableID, egressroutemap.DefaultPrefix, shardSIDs)
}

// EgressPrefixRouteAdd installs egress_route_table's entry for prefix on Linux
// VRF table tableID, encapsulating toward the first usable address in
// shardSIDs.
//
// Two prefixes are installed in practice: ::/0, reaching the IPv6 internet
// through NAT66, and the fabric's NAT64 prefix, reaching the IPv4 internet.
// Both point at the same shard SID -- a shard decides which translation a
// packet gets from its inner destination, not from which route carried it --
// so the NAT64 entry exists to make that prefix reachable where no default
// route covers it, not to steer it elsewhere.
//
// shardSIDs lists the candidate shards. An empty slice installs nothing
// and returns nil, treating "nothing configured yet" as success. A nil or
// unspecified entry is a misconfiguration and fails immediately.
//
// Shards are tried in order and the first that registers wins, rather than
// load being spread across them: correctness matters more here than
// distribution, and per-flow selection would need a hash inside usid_egress.
// A shard whose SID cannot be resolved is skipped, and only an exhausted list
// is an error, because a node that is itself one of the configured shards can
// never resolve a route to its own advertised SID: BGP does not reflect a
// self-originated path back into the originating node's received paths.
// Register resolves link and L2 information as part of the write, which is
// what makes an unresolvable shard fail here.
func EgressPrefixRouteAdd(tableID uint32, prefix *net.IPNet, shardSIDs []net.IP) error {
	if len(shardSIDs) == 0 {
		return nil
	}
	if prefix == nil {
		return errors.New("srv6: EgressPrefixRouteAdd: prefix is nil")
	}
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("srv6: EgressPrefixRouteAdd: %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use

	var unresolved []error
	for _, sid := range shardSIDs {
		// Checked before touching bpffs, as in RouteEgressAdd.
		if sid == nil || sid.IsUnspecified() {
			return fmt.Errorf("refusing to install egress route for %s: shard SID %s is not a usable SRv6 SID",
				prefix, sid)
		}
		if err := table.Register(tableID, prefix, sid); err != nil {
			unresolved = append(unresolved, fmt.Errorf("shard %s: %w", sid, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("no egress shard SID is resolvable yet for %s, out of %d configured: %w",
		prefix, len(shardSIDs), errors.Join(unresolved...))
}

// EgressDefaultRouteDel removes egress_route_table's default (::/0) entry for
// Linux VRF table tableID. The counterpart to EgressDefaultRouteAdd.
func EgressDefaultRouteDel(tableID uint32) error {
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	if err != nil {
		return fmt.Errorf("srv6: EgressDefaultRouteDel: %w", err)
	}
	defer closer.Close() //nolint:errcheck // best-effort close of our own fd, immediately after use
	return table.Unregister(tableID, egressroutemap.DefaultPrefix)
}

// ResolveNodeSourceAddress returns this node's underlay-facing source address:
// the first global-scope IPv6 address on the interface usid_ingress and
// usid_egress are attached to. usid_egress writes it as the source of every
// outer header it pushes. A kernel-native encapsulation would pick it through
// ordinary source-address selection; an in-program header push has to be told.
//
// The interface comes from attach.ResolveInterfaces rather than a separate
// heuristic, so this can never disagree with where the datapath is actually
// attached. Deriving it instead from the main-table default route would pick
// the wrong interface on any node where the default route belongs to the
// cluster network rather than the SRv6 underlay.
func ResolveNodeSourceAddress() (net.IP, error) {
	names, err := attach.ResolveInterfaces()
	if err != nil {
		return nil, fmt.Errorf("resolve SRv6/underlay-facing interface: %w", err)
	}
	if len(names) == 0 {
		return nil, errors.New("attach.ResolveInterfaces returned no interfaces")
	}

	link, err := netlink.LinkByName(names[0])
	if err != nil {
		return nil, fmt.Errorf("look up interface %q: %w", names[0], err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("list addresses on %s: %w", names[0], err)
	}
	for _, a := range addrs {
		if a.Scope == unix.RT_SCOPE_UNIVERSE && !a.IP.IsUnspecified() {
			return a.IP, nil
		}
	}
	return nil, fmt.Errorf("no global-scope IPv6 address found on %s (the SRv6/underlay-facing interface)", names[0])
}

// ResolvePublicUplink returns the fabric uplink's link index and the
// destination and source MACs a DSR backend's VIP-sourced reply is redirected
// toward, regardless of that reply's own destination. See struct
// public_uplink_value in usid.c for how the datapath uses them.
//
// The interface comes from attach.ResolveInterfaces, so this cannot disagree
// with where the datapath is attached. A fabric uplink is point to point and
// has exactly one real neighbor, so this takes the first resolved IPv6
// neighbor on it instead of doing a destination-specific route lookup.
// Returns an error when no neighbor has resolved yet.
func ResolvePublicUplink() (linkIndex int, dmac, smac net.HardwareAddr, err error) {
	names, err := attach.ResolveInterfaces()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("resolve SRv6/underlay-facing interface: %w", err)
	}
	if len(names) == 0 {
		return 0, nil, nil, errors.New("attach.ResolveInterfaces returned no interfaces")
	}

	link, err := netlink.LinkByName(names[0])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("look up interface %q: %w", names[0], err)
	}
	smac = link.Attrs().HardwareAddr
	linkIndex = link.Attrs().Index

	neighs, err := netlink.NeighList(linkIndex, netlink.FAMILY_V6)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("list neighbors on %s: %w", names[0], err)
	}
	for _, n := range neighs {
		// Every IPv6 interface auto-populates a permanent, already-resolved
		// multicast neighbor entry for its group memberships, whether or not
		// any real next hop was ever discovered. Skipping multicast leaves
		// only the genuine neighbor.
		if len(n.HardwareAddr) == 6 && n.IP != nil && !n.IP.IsMulticast() {
			return linkIndex, n.HardwareAddr, smac, nil
		}
	}
	return 0, nil, nil, fmt.Errorf(
		"no resolved neighbor found on %s (the SRv6/underlay-facing interface) -- the underlay hasn't converged yet",
		names[0])
}
