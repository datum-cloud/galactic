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

// routeListFn and linkByIndexFn are package vars so tests can substitute a fake
// netlink view without touching the host network stack.
//
// routeListFn lists routes across every routing table. Passing RT_FILTER_TABLE
// with an unspecified table lifts netlink's default of skipping non-main-table
// routes rather than narrowing to one table. A default route relevant to
// interface selection may legitimately live in a non-main table, such as a
// VRF-scoped underlay, and would otherwise be undetectable.
var (
	routeListFn = func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(netlink.FAMILY_V6,
			&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	}
	linkByIndexFn = func(index int) (netlink.Link, error) {
		return netlink.LinkByIndex(index)
	}
	// linkListFn enumerates every link on the host, for expandBondSlaves.
	// linkByNameFn is declared in health.go and reused here.
	linkListFn = func() ([]netlink.Link, error) {
		return netlink.LinkList()
	}
)

// ResolveInterfaces returns the interface names the uSID datapath should attach
// its TC-BPF ingress hook to.
//
// When config.EnvCNIEBPFInterfaces is set it is parsed as a comma-separated
// list, with whitespace trimmed and duplicates and empty entries removed, and
// used as-is. That is the explicit override for multi-homed nodes where
// auto-detection is ambiguous.
//
// Otherwise interfaces are auto-detected: those carrying the default IPv6
// route first, then those carrying a BGP-learned route, which is where a fabric
// peer's SRv6 traffic arrives when locators travel over a segment the default
// route does not use. Attaching to too few interfaces shows up as silently
// blackholed overlay traffic, so a caller that gets an error here must not
// proceed with a partial or empty set.
//
// Either way the result passes through expandBondSlaves, so an operator using
// the override names only the bond master rather than hand-listing every
// slave.
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

// autoDetectInterfaces returns the deduplicated interface names carrying an
// IPv6 default route or a BGP-learned route, default routes first and within
// each group in the order netlink reports them.
//
// WireGuard links are skipped. A mesh interface can install its own IPv6
// default route alongside the real fabric NIC's, and if netlink reports it
// first, this node's outer-header source address becomes a mesh address that is
// not advertised outside the mesh. Every cross-site packet then leaves
// correctly SID-routed with a source no intermediate network forwards on, and
// is lost with no error at either end. A tunnel can never be the real fabric
// NIC, so the exclusion is by link type rather than by a deployment-specific
// interface name.
//
// Links enslaved to a VRF are skipped for the same reason. The ingress
// sidecar's per-VPC veth pairs pick up a spurious default route in their VRF's
// table, almost certainly from router advertisements between the peers, and
// with several VPCs present that put a link-local-only veth ahead of the real
// NIC. usid_egress then fails open, uncounted, on every encapsulation attempt.
// A VRF slave, sidecar plumbing or tenant attachment alike, can no more be the
// fabric NIC than a tunnel can.
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
				// A route pointing at an interface that will not resolve
				// is not actionable; skip it rather than fail the whole
				// detection over one stale route.
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

	// Default-route interfaces first, and the order is contractual.
	// ResolveNodeSourceAddress takes names[0] and uses that interface's global
	// address as the outer source of every encapsulated packet, which has to
	// stay the interface carrying the default route. A private segment's
	// address is reachable only from that segment, so promoting it would give
	// cross-site traffic a source no intermediate network forwards on.
	collect(isDefaultRoute)
	collect(isFabricPeerRoute)

	if len(names) == 0 {
		return nil, fmt.Errorf(
			"attach: no default or BGP-learned IPv6 route found to auto-detect the "+
				"SRv6/underlay-facing interface; set %s to override", config.EnvCNIEBPFInterfaces)
	}
	return names, nil
}

// isFabricPeerRoute reports whether r was learned over BGP, making r's
// interface one where a fabric peer, and so SRv6-encapsulated traffic from it,
// can arrive.
//
// Default-route detection alone is not enough. Encapsulated traffic arrives
// wherever a peer's route to this node's locator points, which need not be the
// default route's interface: a fabric can carry locators over a private segment
// reached by a specific route. When that happens and the hook is attached only
// to the public NIC, correctly formed SRv6 packets arrive on the other
// interface, nothing decapsulates them, and the kernel counts them as
// Ip6InHdrErrors because all it sees is a local SID with no action. Nothing
// reports an error while the tenant datapath is dead.
//
// BGP is the signal because a fabric peer is by definition one this node
// exchanges routes with, so the interface reaching it carries a BGP-learned
// route whatever addressing the segment uses. That holds for a peer in this
// node's own uSID Block and for one in a different Block, which a rule keyed on
// locator address space would not. The exclusions applied to default routes
// matter more here: EVPN routes for tenant prefixes are BGP-learned too, and
// every one points into a VRF.
func isFabricPeerRoute(r netlink.Route) bool {
	if r.Protocol != unix.RTPROT_BGP {
		return false
	}
	// A discard route is not a path to anything. The locator and aggregate
	// prefixes this node originates are installed as blackholes on lo, so
	// without this every node originating an aggregate would nominate lo as a
	// fabric interface. Non-forwarding types are rejected rather than unicast
	// required, because some netlink paths report an ordinary unicast route as
	// RTN_UNSPEC and requiring unicast would match nothing.
	switch r.Type {
	case unix.RTN_BLACKHOLE, unix.RTN_UNREACHABLE, unix.RTN_PROHIBIT:
		return false
	}
	return true
}

// excludedLinkType is the netlink Link.Type() autoDetectInterfaces never treats
// as a candidate fabric interface.
const excludedLinkType = "wireguard"

// excludedMasterType is the netlink Link.Type() a link's master is checked
// against by isVRFSlave.
const excludedMasterType = "vrf"

// isVRFSlave reports whether link is enslaved to a Linux VRF master. The master
// is resolved rather than link's own Type() trusted, because a VRF slave still
// reports its underlying type and only the master marks the enslavement. That
// keeps this to links genuinely in a VRF: a bond slave, which expandBondSlaves
// wants included, is never also a VRF slave on any topology this codebase
// creates.
func isVRFSlave(link netlink.Link) bool {
	idx := link.Attrs().MasterIndex
	if idx <= 0 {
		return false
	}
	master, err := linkByIndexFn(idx)
	if err != nil {
		// An unresolvable master is not actionable; do not exclude on a
		// guess.
		return false
	}
	return master.Type() == excludedMasterType
}

// expandBondSlaves expands any bonding master in names to include its slaves,
// does the same for a VLAN sitting on top of a bond, and leaves every other
// interface unchanged.
//
// RX ingress tc classification on a bond happens on the slave devices, not the
// master. The master still carries the addresses and routes ResolveInterfaces
// detects from, or that an operator names directly, but a hook attached only
// there never sees traffic that arrives while bonded, and every datapath
// counter stays at zero while packets arrive on the wire. Attaching both master
// and slaves is what removes the need to hand-list slave names in the override.
//
// A name that does not resolve is passed through and logged rather than failed.
// The override path has never required its interfaces to exist at resolution
// time, since conflist generation resolves names purely to produce a config
// string. A caller that needs the interface to exist still gets that failure at
// attach time. Once a name does resolve to a real bonding master, though,
// failing to enumerate its slaves is fatal: falling back to the master alone
// would reproduce the bug this exists to fix.
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
			// Not a bond itself, but it may sit on one: a VLAN over a
			// bond has the same problem one level up.
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

// vlanBondMaster returns the bonding master a VLAN interface sits on, or nil
// when link is not a VLAN or its parent is not a bond.
//
// A VLAN over a bond inherits the bond master's ingress problem rather than
// escaping it. RX classification still happens on the physical slaves, so a
// filter on the VLAN device never runs for traffic arriving while bonded, just
// as a filter on the bond master never does. Packets show up in a capture on
// the VLAN device, because the packet tap runs where tc classification does
// not, while the datapath's counters stay flat.
//
// The parent's slaves are what get added, not the parent itself, since
// attaching to a bond master is inert for the same reason.
//
// The tag is handled in the datapath, not here. NICs that strip it in hardware
// leave the frame at tc with ethertype IPv6 and the VLAN id in skb metadata,
// which usid_ingress pops before redirecting. A deployment whose NICs leave the
// tag in packet data would additionally need 802.1Q parsing, which the datapath
// does not have.
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
