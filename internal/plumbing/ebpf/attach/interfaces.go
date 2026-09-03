// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/bond"
)

// routeListFn and linkByIndexFn are package-level function variables so
// tests can substitute a fake netlink view without touching the real host
// network stack -- the same override-var pattern internal/installer uses
// for addrListFn.
//
// routeListFn deliberately lists routes across every routing table, not
// just the main table: passing RT_FILTER_TABLE with an unfiltered
// (RT_TABLE_UNSPEC) Table lifts vishvananda/netlink's own default of
// skipping any non-main-table route, rather than narrowing the result to
// one specific table. A default route relevant to this node's
// underlay/overlay interface selection may legitimately live in a
// non-main table (e.g. a VRF-scoped underlay), and restricting
// auto-detection to the main table only would make that topology
// undetectable -- the caller (autoDetectInterfaces) still just looks for
// any IPv6 default route, wherever it lives, exactly as before.
var (
	routeListFn = func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(netlink.FAMILY_V6,
			&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	}
	linkByIndexFn = func(index int) (netlink.Link, error) {
		return netlink.LinkByIndex(index)
	}
	// linkListFn enumerates every link on the host, for expandBondSlaves'
	// slave lookup below. linkByNameFn (resolving one name to its Link) is
	// already declared in health.go -- reused here rather than redeclared.
	linkListFn = func() ([]netlink.Link, error) {
		return netlink.LinkList()
	}
)

// ResolveInterfaces returns the set of interface names the uSID datapath
// should attach its TC-BPF ingress hook to (design plan §4.1).
//
// If config.EnvCNIEBPFInterfaces is set, it is parsed as a comma-separated
// list of interface names (whitespace trimmed, duplicates and empty
// entries removed) and used directly -- no auto-detection is performed.
// This is the explicit override for multi-homed nodes where auto-detection
// is ambiguous.
//
// Otherwise the interfaces are auto-detected: those carrying the default
// IPv6 route, followed by those carrying a BGP-learned route, which is
// where a fabric peer's SRv6 traffic arrives when the locators travel over
// a segment the default route does not use (see isFabricPeerRoute).
// Attaching to the wrong (or too few) interfaces fails as silent
// blackholing of overlay traffic (design plan §4.1), so callers that get
// an error here must not proceed with a partial or empty interface set.
//
// Either way, the resolved set is then run through expandBondSlaves: any
// interface that is itself a Linux bonding master is expanded to include
// its slave interfaces too, since ingress tc/eBPF classification on a
// bonded interface happens on the slaves, not the master -- see
// expandBondSlaves' own doc comment. This applies uniformly to both paths
// above, so an operator using the override only needs to name the bond
// master, not hand-list every slave alongside it.
func ResolveInterfaces() ([]string, error) {
	var (
		names []string
		err   error
	)
	if override := strings.TrimSpace(os.Getenv(config.EnvCNIEBPFInterfaces)); override != "" {
		names = parseInterfaceList(override)
		if len(names) == 0 {
			return nil, fmt.Errorf("attach: %s is set to %q but contains no usable interface names",
				config.EnvCNIEBPFInterfaces, override)
		}
	} else {
		names, err = autoDetectInterfaces()
		if err != nil {
			return nil, err
		}
	}
	return expandBondSlaves(names)
}

// parseInterfaceList splits a comma-separated interface list, trimming
// whitespace and removing duplicate/empty entries while preserving order.
func parseInterfaceList(v string) []string {
	var out []string
	seen := make(map[string]bool)
	for part := range strings.SplitSeq(v, ",") {
		name := strings.TrimSpace(part)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// autoDetectInterfaces returns the deduplicated set of interface names
// carrying an IPv6 default route (::/0) or a BGP-learned route, default
// routes first, and within each group in the order netlink reports them
// -- analogous to the existing GALACTIC_ROUTER_BGP_LOCAL_ADDRESS
// auto-detection-from-`lo` pattern (internal/plumbing/loaddr), but over
// routes rather than addresses.
//
// Skips wireguard-type links (excludedLinkType): a WireGuard mesh
// interface can install its own IPv6 default-ish route alongside the real
// fabric NIC's, and if netlink reports the mesh interface's route first,
// ResolveNodeSourceAddress would bake the mesh interface's ULA in as this
// node's SRv6 outer-header source address for every encapsulated packet.
// That address is never reachable off-node (it's not advertised anywhere
// outside the WireGuard mesh), so every cross-site SRv6 packet would leave
// the box correctly SID-routed but with a source no intermediate network
// would forward on (or a receiving node would recognize as this peer) --
// silent packet loss with no error on either side. A WireGuard tunnel can
// never legitimately be "the real fabric NIC" this datapath pushes raw
// SRv6-encapsulated Ethernet frames onto, so it's excluded categorically
// rather than by interface name (the specific mesh interface name is
// deployment-specific; the underlying failure mode -- a tunnel interface
// racing a real NIC for the default route -- is not).
//
// Also skips any interface enslaved to a Linux VRF master (excludedMasterType),
// for the identical reasoning, confirmed live: internal/ingresssidecar's
// own per-VPC veth pair (ensureEgressDatapath's ivpN/ivsN, enslaved into
// that VPC's VRF so usid_egress has a real ingress hook to attach to --
// see that function's own doc comment) picks up a spurious
// `default via fe80::... dev ivsN table <vrf>` route, almost certainly
// from IPv6 router-solicitation/advertisement between the veth peers. With
// six VPCs' VRFs present, that put ivs1 (the lowest VRF table id) ahead of
// eth0 in this function's own result, so ResolveNodeSourceAddress
// permanently resolved a link-local-only interface instead of the real
// fabric NIC -- ensureEgressDatapath's own doc comment confirms the
// consequence isn't cosmetic: usid_egress fails open (TC_ACT_UNSPEC,
// uncounted) on every encapsulation attempt until this resolves. A VRF
// slave -- this sidecar's own internal plumbing or a real tenant
// attachment either one -- can never legitimately be "the real fabric NIC"
// any more than a WireGuard mesh interface can.
func autoDetectInterfaces() ([]string, error) {
	routes, err := routeListFn()
	if err != nil {
		return nil, fmt.Errorf("attach: list IPv6 routes for auto-detection: %w", err)
	}

	var names []string
	seen := make(map[string]bool)
	collect := func(match func(netlink.Route) bool) {
		for _, r := range routes {
			if !match(r) || r.LinkIndex <= 0 {
				continue
			}
			link, err := linkByIndexFn(r.LinkIndex)
			if err != nil {
				// A route pointing at an interface we can't resolve isn't
				// actionable here; skip it rather than failing the whole
				// detection over one stale/racing route.
				continue
			}
			if link.Type() == excludedLinkType {
				continue
			}
			if isVRFSlave(link) {
				continue
			}
			if link.Attrs().Flags&net.FlagLoopback != 0 {
				continue
			}
			name := link.Attrs().Name
			if seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}

	// Default-route interfaces first, and the ordering is contractual, not
	// cosmetic: ResolveNodeSourceAddress takes names[0] and uses that
	// interface's global address as the outer source of every packet this
	// node encapsulates. That has to stay the interface carrying the
	// default route. A private fabric segment's address is reachable only
	// from that segment, so promoting it here would give cross-site SRv6
	// a source no intermediate network forwards on -- the same silent loss
	// the wireguard exclusion above exists to prevent.
	collect(isDefaultRoute)
	collect(isFabricPeerRoute)

	if len(names) == 0 {
		return nil, fmt.Errorf(
			"attach: no default or BGP-learned IPv6 route found to auto-detect the "+
				"SRv6/underlay-facing interface; set %s to override", config.EnvCNIEBPFInterfaces)
	}
	return names, nil
}

// isFabricPeerRoute reports whether r is a route this node's own routing
// daemon learned over BGP, making r's interface one where a fabric peer --
// and so SRv6-encapsulated traffic from it -- can arrive.
//
// Default-route detection alone is not enough, and the gap is not
// theoretical. Encapsulated traffic arrives wherever a peer's route to
// this node's locator points, which is not necessarily the default route's
// interface: a fabric can carry its locators over a private segment shared
// only by the nodes on it, reached by a specific route rather than the
// default. Measured on such a pair -- iBGP and the locators over a VLAN on
// a private bond, the default route still on the public NIC -- 10
// correctly-formed SRv6 packets arrived on the VLAN, the ingress hook was
// attached only to the public NIC, nothing was decapsulated, and the
// kernel counted them as Ip6InHdrErrors because a local SID with no
// seg6local action is all it saw. No error anywhere: the tenant datapath
// was silently dead.
//
// BGP is the signal because a fabric peer is by definition one this node
// exchanges routes with, so the interface reaching it carries a
// BGP-learned route whatever addressing the segment uses. It holds for a
// peer in this node's own uSID Block and for one in a different Block,
// which a rule keyed on locator address space would not. The exclusions
// applied to default routes apply here unchanged, and they matter more:
// EVPN routes for tenant prefixes are BGP-learned too, and every one of
// them points into a VRF, which isVRFSlave rejects.
func isFabricPeerRoute(r netlink.Route) bool {
	if r.Protocol != unix.RTPROT_BGP {
		return false
	}
	// A discard is not a path to anything. FRR installs the locator and
	// aggregate prefixes this node originates itself as blackholes, and
	// reports them on lo, so without this every node with an originated
	// aggregate would nominate lo as a fabric interface. Rejecting the
	// known non-forwarding types rather than requiring RTN_UNICAST, because
	// an ordinary unicast route is also reported as RTN_UNSPEC by some
	// netlink paths and requiring unicast would then match nothing.
	switch r.Type {
	case unix.RTN_BLACKHOLE, unix.RTN_UNREACHABLE, unix.RTN_PROHIBIT:
		return false
	}
	return true
}

// excludedLinkType is the vishvananda/netlink Link.Type() value
// autoDetectInterfaces never treats as a candidate fabric interface -- see
// autoDetectInterfaces' own doc comment for why.
const excludedLinkType = "wireguard"

// excludedMasterType is the vishvananda/netlink Link.Type() value a link's
// *master* is checked against by isVRFSlave -- see autoDetectInterfaces'
// own doc comment for why a VRF slave is excluded the same way a
// WireGuard link is.
const excludedMasterType = "vrf"

// isVRFSlave reports whether link is enslaved to a Linux VRF master.
// Resolves the master via linkByIndexFn rather than trusting link's own
// Type() (a VRF slave is still reported as its real underlying type --
// "veth", "bond", etc. -- only the separate MasterIndex/master-side
// SlaveKind marks the enslavement), so this only ever excludes a link that
// genuinely belongs to a VRF, not every enslaved link (a bond slave, which
// expandBondSlaves deliberately wants included, is never itself a VRF
// slave at the same time on any topology this codebase creates).
func isVRFSlave(link netlink.Link) bool {
	idx := link.Attrs().MasterIndex
	if idx <= 0 {
		return false
	}
	master, err := linkByIndexFn(idx)
	if err != nil {
		// Master unresolvable isn't actionable here; don't exclude on a
		// guess -- matches autoDetectInterfaces' own stance on an
		// unresolvable route target just above.
		return false
	}
	return master.Type() == excludedMasterType
}

// expandBondSlaves expands any bonding-master interface in names to also
// include its slave interfaces, and does the same for a VLAN interface
// sitting on top of a bond (vlanBondMaster), leaving every other interface
// unchanged.
//
// On a Linux bonding master, RX ingress tc/eBPF classification happens on
// the slave devices, not the bond master itself -- a well-known kernel
// behavior (confirmed live: `tc filter show dev bond0 ingress` showed this
// package's own filter correctly attached, `tc filter show dev <slave>
// ingress` showed nothing on either slave, and every uSID datapath map
// counter -- locator_table, function_table, vrf_table, drop_reasons --
// stayed at zero despite tcpdump confirming packets arriving on the wire).
// The bond master still carries the IP/route configuration ResolveInterfaces
// resolves from (auto-detect) or an operator names directly (the
// GALACTIC_CNI_EBPF_INTERFACES override), but attaching the ingress hook to
// only the master silently never sees any traffic that arrives while
// bonded -- so both master and slaves are attached, mirroring the
// tc/bonding gotcha this replaces the historical per-node "list the master
// plus every slave name in GALACTIC_CNI_EBPF_INTERFACES by hand" workaround.
//
// A name that can't be resolved at all is passed through unchanged (logged,
// not failed): ResolveInterfaces' override path has never required its
// named interfaces to actually exist on the host at resolution time (e.g.
// internal/installer's static-conflist generation resolves this purely to
// produce a config string, independent of whether/when this init
// container's netns can see the interface) -- callers that do need the
// interface to genuinely exist still get that failure from attachOne at
// actual attach time, unchanged from before this function existed. Once a
// name does resolve to a real bonding master, though, failing to enumerate
// its slaves is treated as fatal -- silently falling back to "just the
// master" would reproduce the exact bug this function exists to fix.
func expandBondSlaves(names []string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	add := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}

	for _, name := range names {
		add(name)

		link, err := linkByNameFn(name)
		if err != nil {
			slog.Warn("attach: could not resolve interface to check whether it's a bonding master, "+
				"leaving it as-is", "interface", name, "err", err)
			continue
		}

		master := link
		if !bond.IsMaster(master) {
			// Not a bond itself. It may still sit on top of one: a VLAN
			// over a bond has the same problem as the bond master, one
			// level further up. See vlanBondMaster.
			master = vlanBondMaster(link)
			if master == nil {
				continue
			}
		}

		links, err := linkListFn()
		if err != nil {
			return nil, fmt.Errorf("attach: enumerate slaves of bonding master %q: %w",
				master.Attrs().Name, err)
		}
		for _, slave := range bond.SlaveNames(master, links) {
			add(slave)
		}
	}
	return out, nil
}

// vlanBondMaster returns the bonding master a VLAN interface sits on top of,
// or nil when link is not a VLAN or its parent is not a bond.
//
// A VLAN over a bond inherits the bond master's ingress problem rather than
// escaping it. RX classification still happens on the physical slaves, so a
// filter on the VLAN device never runs for traffic that arrives while
// bonded, exactly as a filter on the bond master never does.
//
// Measured on a fabric carrying its locators over a VLAN on a private bond,
// with the ingress hook attached to the VLAN device: SRv6 packets arrived
// (pcap on the VLAN device showed them, since the packet tap runs where tc
// classification does not), the datapath's own counters did not move at all,
// and nothing was decapsulated. Attaching to the parent bond's slaves moved
// the per-VRF packet counter by exactly the number of packets sent, and
// detaching them stopped it again.
//
// The parent's own slaves are what gets added, not the parent: attaching to
// a bond master is inert for the same reason, so naming it would achieve
// nothing.
//
// The tag is not a problem here. These NICs strip it in hardware, so the
// frame reaching tc on the slave carries ethertype IPv6 with the VLAN id in
// skb metadata, which is what usid_ingress's Ethernet parse already
// expects. A deployment whose NICs leave the tag in the packet data would
// additionally need 802.1Q parsing in the datapath, which it does not have.
func vlanBondMaster(link netlink.Link) netlink.Link {
	if link.Type() != vlanLinkType {
		return nil
	}
	idx := link.Attrs().ParentIndex
	if idx <= 0 {
		return nil
	}
	parent, err := linkByIndexFn(idx)
	if err != nil {
		// Unresolvable parent isn't actionable; don't guess, matching this
		// package's stance on an unresolvable route target and master.
		slog.Warn("attach: could not resolve a VLAN interface's parent to check whether it's a "+
			"bonding master", "interface", link.Attrs().Name, "parentIndex", idx, "err", err)
		return nil
	}
	if !bond.IsMaster(parent) {
		return nil
	}
	return parent
}

// vlanLinkType is the vishvananda/netlink Link.Type() value identifying a
// VLAN interface, whose parent vlanBondMaster checks for bonding.
const vlanLinkType = "vlan"

// isDefaultRoute reports whether r is an IPv6 default route (::/0).
func isDefaultRoute(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, bits := r.Dst.Mask.Size()
	return ones == 0 && bits == 128
}
