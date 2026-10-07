// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// ErrNoShardResolvable is wrapped by EgressPrefixRouteAdd and
// EgressPrefixRouteAddTo when not one configured shard SID has a resolvable
// route and neighbor.
var ErrNoShardResolvable = errors.New("no egress shard SID is resolvable")

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
// Two kinds of prefix are installed in practice: ::/0, reaching the IPv6
// internet through NAT66, and each of the fabric's NAT64 prefixes, reaching
// the IPv4 internet.
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
	return EgressPrefixRouteAddTo(table, tableID, prefix, shardSIDs)
}

// EgressPrefixRouteAddTo is EgressPrefixRouteAdd against an egress_route_table
// the caller has already opened. Shard selection and error behavior are
// identical; an empty shardSIDs installs nothing and returns nil.
func EgressPrefixRouteAddTo(
	table *egressroutemap.EgressRouteTable, tableID uint32, prefix *net.IPNet, shardSIDs []net.IP,
) error {
	if len(shardSIDs) == 0 {
		return nil
	}
	if prefix == nil {
		return errors.New("srv6: EgressPrefixRouteAddTo: prefix is nil")
	}

	var unresolved []error
	for _, sid := range shardSIDs {
		// Checked before writing the entry, as in RouteEgressAdd.
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
	return fmt.Errorf("%w yet for %s, out of %d configured: %w",
		ErrNoShardResolvable, prefix, len(shardSIDs), errors.Join(unresolved...))
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
